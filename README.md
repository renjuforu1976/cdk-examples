version: 0.2
phases:
install:
commands:
- echo “Installing jq for JSON parsing…”
- apt-get update -qq && apt-get install -y -qq jq
build:
commands:
- echo “=========================================”
- echo “ PRODUCTION SECURITY GATE”
- echo “=========================================”


  # Resolve digest from pipeline environment variable
  - echo "Resolving image digest for deployment..."
  - echo "SNS_TOPIC_ARN=${SNS_TOPIC_ARN}"
  - echo "S3_BUCKET=${S3_BUCKET}"
  - echo "IMAGE_TAG=${IMAGE_TAG}"
  - echo "IMAGE_NAME=${IMAGE_NAME}"
  - echo "ECR_SOURCE_DIGEST=${ECR_SOURCE_DIGEST}"
  - DEPLOY_DIGEST=$(echo "$ECR_SOURCE_DIGEST" | cut -d ':' -f2 | head -c 12)
  - |
    if [ -z "$DEPLOY_DIGEST" ]; then
      echo "ERROR: Could not resolve image digest for $IMAGE_NAME:$IMAGE_TAG"
      aws sns publish \
        --topic-arn "$SNS_TOPIC_ARN" \
        --subject "SECURITY GATE FAILED - $IMAGE_NAME - Image Digest Not Found" \
        --message "SECURITY GATE FAILURE

    Application: $IMAGE_NAME
    Image Tag: $IMAGE_TAG
    Status: FAILED
    Reason: Could not resolve image digest. ECR_SOURCE_DIGEST was empty.
    Action Required: Verify the image exists in ECR and re-run the pipeline.
    Pipeline: $CODEBUILD_BUILD_URL"
      exit 1
    fi
  - echo "Image: $IMAGE_NAME:$IMAGE_TAG"
  - echo "Digest: $DEPLOY_DIGEST"

  # Verify SAST scan exists for this digest
  - echo ""
  - echo "--- Checking SAST scan ---"
  - |
    SAST_FILE=$(aws s3 ls "s3://${S3_BUCKET}/ent-svc-scan-results/${IMAGE_NAME}/sast/" \
      | grep "$DEPLOY_DIGEST" \
      | awk '{print $4}' \
      | head -n 1)
    if [ -z "$SAST_FILE" ]; then
      echo "FAIL: No SAST scan found for image digest $DEPLOY_DIGEST"
      aws sns publish \
        --topic-arn "$SNS_TOPIC_ARN" \
        --subject "SECURITY GATE FAILED - $IMAGE_NAME - SAST Scan Missing" \
        --message "SECURITY GATE FAILURE

    Application: $IMAGE_NAME
    Image Tag: $IMAGE_TAG
    Image Digest: $DEPLOY_DIGEST
    Status: FAILED
    Reason: No SAST scan results found for this image digest.
    This image has NOT been through static analysis security testing.
    Action Required: Run the Master CI pipeline to scan this image before deploying to production.
    S3 Path Checked: s3://${S3_BUCKET}/ent-svc-scan-results/${IMAGE_NAME}/sast/
    Pipeline: $CODEBUILD_BUILD_URL"
      exit 1
    fi
    echo "SAST scan found: $SAST_FILE"
  - aws s3 cp "s3://${S3_BUCKET}/ent-svc-scan-results/${IMAGE_NAME}/sast/$SAST_FILE" sast-results.json

  # Verify SCA scan exists for this digest
  - echo ""
  - echo "--- Checking SCA scan ---"
  - |
    SCA_FILE=$(aws s3 ls "s3://${S3_BUCKET}/ent-svc-scan-results/${IMAGE_NAME}/sca/" \
      | grep "$DEPLOY_DIGEST" \
      | awk '{print $4}' \
      | head -n 1)
    if [ -z "$SCA_FILE" ]; then
      echo "FAIL: No SCA scan found for image digest $DEPLOY_DIGEST"
      aws sns publish \
        --topic-arn "$SNS_TOPIC_ARN" \
        --subject "SECURITY GATE FAILED - $IMAGE_NAME - SCA Scan Missing" \
        --message "SECURITY GATE FAILURE

    Application: $IMAGE_NAME
    Image Tag: $IMAGE_TAG
    Image Digest: $DEPLOY_DIGEST
    Status: FAILED
    Reason: No SCA scan results found for this image digest.
    This image has NOT been through software composition analysis.
    Action Required: Run the Master CI pipeline to scan this image before deploying to production.
    S3 Path Checked: s3://${S3_BUCKET}/ent-svc-scan-results/${IMAGE_NAME}/sca/
    Pipeline: $CODEBUILD_BUILD_URL"
      exit 1
    fi
    echo "SCA scan found: $SCA_FILE"
  - aws s3 cp "s3://${S3_BUCKET}/ent-svc-scan-results/${IMAGE_NAME}/sca/$SCA_FILE" sca-results.json

  # Verify SBOM exists for this digest
  - echo ""
  - echo "--- Checking SBOM ---"
  - |
    SBOM_FILE=$(aws s3 ls "s3://${S3_BUCKET}/ent-svc-scan-results/${IMAGE_NAME}/sbom/" \
      | grep "$DEPLOY_DIGEST" \
      | awk '{print $4}' \
      | head -n 1)
    if [ -z "$SBOM_FILE" ]; then
      echo "WARNING: No SBOM found for image digest $DEPLOY_DIGEST"
    else
      echo "SBOM found: $SBOM_FILE"
    fi

  # Check scan age
  - echo ""
  - echo "--- Checking scan freshness ---"
  - |
    SCAN_DATE=$(echo "$SAST_FILE" | grep -oP '^\d{8}' || echo "")
    TODAY=$(date -u +"%Y%m%d")
    DAYS_OLD=0
    if [ -n "$SCAN_DATE" ]; then
      DAYS_OLD=$(( ($(date -d "$TODAY" +%s) - $(date -d "$SCAN_DATE" +%s)) / 86400 ))
      echo "Scan date: $SCAN_DATE (${DAYS_OLD} days old)"
      if [ "$DAYS_OLD" -gt 7 ]; then
        echo "WARNING: Scan is more than 7 days old."
      fi
    fi

  # Validate SAST results
  - echo ""
  - echo "--- Validating SAST results ---"
  - |
    SAST_TOTAL=$(cat sast-results.json | jq '.findings | length' 2>/dev/null || echo "0")
    SAST_VERY_HIGH=$(cat sast-results.json | jq '[.findings[] | select(.severity >= 5)] | length' 2>/dev/null || echo "0")
    SAST_HIGH=$(cat sast-results.json | jq '[.findings[] | select(.severity == 4)] | length' 2>/dev/null || echo "0")
    SAST_MEDIUM=$(cat sast-results.json | jq '[.findings[] | select(.severity == 3)] | length' 2>/dev/null || echo "0")
    SAST_LOW=$(cat sast-results.json | jq '[.findings[] | select(.severity <= 2)] | length' 2>/dev/null || echo "0")
    SAST_BLOCK=$(cat sast-results.json | jq '[.findings[] | select(.severity >= 4)] | length' 2>/dev/null || echo "0")

    echo "SAST Total findings: $SAST_TOTAL"
    echo "  Very High: $SAST_VERY_HIGH"
    echo "  High: $SAST_HIGH"
    echo "  Medium: $SAST_MEDIUM"
    echo "  Low: $SAST_LOW"

    SAST_DETAILS=""
    if [ "$SAST_BLOCK" -gt 0 ]; then
      echo ""
      echo "SAST BLOCKING FINDINGS:"
      SAST_DETAILS=$(cat sast-results.json | jq -r '.findings[] | select(.severity >= 4) | "  - \(.title) | Severity: \(.severity) | CWE: \(.cwe_id) | File: \(.files.source_file.file)"')
      echo "$SAST_DETAILS"
      SAST_PASS=false
    else
      SAST_PASS=true
    fi

  # Validate SCA results
  - echo ""
  - echo "--- Validating SCA results ---"
  - |
    SCA_CRITICAL=$(cat sca-results.json | jq '[.records[]? | select(.vulnerabilities[]?.cvssScore >= 9.0)] | length' 2>/dev/null || echo "0")
    SCA_HIGH=$(cat sca-results.json | jq '[.records[]? | select(.vulnerabilities[]?.cvssScore >= 7.0 and .vulnerabilities[]?.cvssScore < 9.0)] | length' 2>/dev/null || echo "0")
    SCA_MEDIUM=$(cat sca-results.json | jq '[.records[]? | select(.vulnerabilities[]?.cvssScore >= 4.0 and .vulnerabilities[]?.cvssScore < 7.0)] | length' 2>/dev/null || echo "0")
    SCA_BLOCK=$(cat sca-results.json | jq '[.records[]? | select(.vulnerabilities[]?.cvssScore >= 7.0)] | length' 2>/dev/null || echo "0")

    echo "SCA Vulnerable libraries:"
    echo "  Critical (CVSS >= 9.0): $SCA_CRITICAL"
    echo "  High (CVSS >= 7.0): $SCA_HIGH"
    echo "  Medium (CVSS >= 4.0): $SCA_MEDIUM"

    SCA_DETAILS=""
    if [ "$SCA_BLOCK" -gt 0 ]; then
      echo ""
      echo "SCA BLOCKING FINDINGS:"
      SCA_DETAILS=$(cat sca-results.json | jq -r '.records[]? | select(.vulnerabilities[]?.cvssScore >= 7.0) | "  - \(.component_id) | \(.vulnerabilities[]? | select(.cvssScore >= 7.0) | "CVSS: \(.cvssScore) - \(.title)")"')
      echo "$SCA_DETAILS"
      SCA_PASS=false
    else
      SCA_PASS=true
    fi

  # Final gate decision and notification
  - |
    echo ""
    echo "============================================="
    echo " PRODUCTION SECURITY GATE SUMMARY "
    echo "============================================="
    echo " Image: $IMAGE_NAME:$IMAGE_TAG"
    echo " Digest: $DEPLOY_DIGEST"
    echo " SAST Scan: $SAST_FILE"
    echo " SCA Scan: $SCA_FILE"
    echo " SBOM: ${SBOM_FILE:-NOT FOUND}"
    echo " Scan Age: ${DAYS_OLD} days"
    echo "---------------------------------------------"
    echo " SAST: $([ "$SAST_PASS" = "true" ] && echo "PASSED" || echo "FAILED")"
    echo " SCA: $([ "$SCA_PASS" = "true" ] && echo "PASSED" || echo "FAILED")"
    echo "============================================="
    echo ""

    if [ "$SAST_PASS" = "false" ] || [ "$SCA_PASS" = "false" ]; then
      echo "SECURITY GATE: FAILED"
      echo "Sending notification to management..."

      FINDINGS_MSG=""
      if [ "$SAST_PASS" = "false" ]; then
        FINDINGS_MSG="${FINDINGS_MSG}
    SAST FINDINGS (High/VeryHigh): $SAST_BLOCK
      - Very High: $SAST_VERY_HIGH
      - High: $SAST_HIGH
    Details:
    $SAST_DETAILS
    "
      fi

      if [ "$SCA_PASS" = "false" ]; then
        FINDINGS_MSG="${FINDINGS_MSG}
    SCA FINDINGS (CVSS >= 7.0): $SCA_BLOCK
      - Critical (CVSS >= 9.0): $SCA_CRITICAL
      - High (CVSS >= 7.0): $SCA_HIGH
    Details:
    $SCA_DETAILS
    "
      fi

      aws sns publish \
        --topic-arn "$SNS_TOPIC_ARN" \
        --subject "SECURITY GATE FAILED - $IMAGE_NAME - High/Critical Vulnerabilities Found" \
        --message "SECURITY GATE FAILURE - VULNERABILITIES DETECTED

    =============================================
    PRODUCTION DEPLOYMENT BLOCKED
    =============================================

    Application: $IMAGE_NAME
    Image Tag: $IMAGE_TAG
    Image Digest: $DEPLOY_DIGEST
    Scan Age: ${DAYS_OLD} days

    SAST Result: $([ "$SAST_PASS" = "true" ] && echo "PASSED" || echo "FAILED")
    SCA Result: $([ "$SCA_PASS" = "true" ] && echo "PASSED" || echo "FAILED")

    =============================================
    VULNERABILITY DETAILS
    =============================================
    $FINDINGS_MSG

    =============================================
    ACTION REQUIRED
    =============================================
    1. Review the findings above
    2. Fix the vulnerabilities and re-run the CI pipeline
    3. OR request a management exception to proceed

    Scan Results:
      - SAST: s3://${S3_BUCKET}/ent-svc-scan-results/${IMAGE_NAME}/sast/$SAST_FILE
      - SCA: s3://${S3_BUCKET}/ent-svc-scan-results/${IMAGE_NAME}/sca/$SCA_FILE

    Pipeline: $CODEBUILD_BUILD_URL"

      exit 1
    else
      echo "SECURITY GATE: PASSED"
      echo "Image $DEPLOY_DIGEST is approved for production deployment."

      aws sns publish \
        --topic-arn "$SNS_TOPIC_ARN" \
        --subject "SECURITY GATE PASSED - $IMAGE_NAME - Approved for Production" \
        --message "SECURITY GATE PASSED

    =============================================
    PRODUCTION DEPLOYMENT APPROVED
    =============================================

    Application: $IMAGE_NAME
    Image Tag: $IMAGE_TAG
    Image Digest: $DEPLOY_DIGEST
    Scan Age: ${DAYS_OLD} days

    SAST Result: PASSED (Total: $SAST_TOTAL, High/VeryHigh: 0)
    SCA Result: PASSED (Critical: $SCA_CRITICAL, High: 0)

    Scan Results:
      - SAST: s3://${S3_BUCKET}/ent-svc-scan-results/${IMAGE_NAME}/sast/$SAST_FILE
      - SCA: s3://${S3_BUCKET}/ent-svc-scan-results/${IMAGE_NAME}/sca/$SCA_FILE
      - SBOM: s3://${S3_BUCKET}/ent-svc-scan-results/${IMAGE_NAME}/sbom/${SBOM_FILE:-N/A}

    This image is approved for production deployment.
    Manual approval is still required in the pipeline.

    Pipeline: $CODEBUILD_BUILD_URL"
    fi
