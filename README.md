# ... after PASSED/FAILED SNS notifications but before fi ...

# Archive scan results to audit bucket (always, regardless of pass/fail)
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
AUDIT_PATH="security-audits/${IMAGE_NAME}/${TIMESTAMP}_${DEPLOY_DIGEST}"
GATE_RESULT="UNKNOWN"
if [ "$SAST_PASS" = "true" ] && [ "$SCA_PASS" = "true" ]; then
  GATE_RESULT="PASSED"
else
  GATE_RESULT="FAILED"
fi

echo "Archiving scan results to audit bucket..."
aws s3 cp sast-results.json "s3://${AUDIT_BUCKET}/${AUDIT_PATH}/sast-results.json"
aws s3 cp sca-results.json "s3://${AUDIT_BUCKET}/${AUDIT_PATH}/sca-results.json"

if [ -n "$SBOM_FILE" ]; then
  aws s3 cp "s3://${S3_BUCKET}/ent-svc-scan-results/${IMAGE_NAME}/sbom/$SBOM_FILE" "s3://${AUDIT_BUCKET}/${AUDIT_PATH}/sbom.json"
fi

cat > deployment-metadata.json << EOF
{
  "application": "$IMAGE_NAME",
  "imageTag": "$IMAGE_TAG",
  "imageDigest": "$DEPLOY_DIGEST",
  "deploymentDate": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "gateResult": "$GATE_RESULT",
  "sastResult": "$([ "$SAST_PASS" = "true" ] && echo "PASSED" || echo "FAILED")",
  "sastFindings": {
    "total": $SAST_TOTAL,
    "veryHigh": $SAST_VERY_HIGH,
    "high": $SAST_HIGH,
    "medium": $SAST_MEDIUM,
    "low": $SAST_LOW
  },
  "scaResult": "$([ "$SCA_PASS" = "true" ] && echo "PASSED" || echo "FAILED")",
  "scaFindings": {
    "critical": $SCA_CRITICAL,
    "high": $SCA_HIGH,
    "medium": $SCA_MEDIUM
  },
  "pipeline": "$CODEBUILD_BUILD_URL"
}
EOF
aws s3 cp deployment-metadata.json "s3://${AUDIT_BUCKET}/${AUDIT_PATH}/deployment-metadata.json"
echo "Archived to s3://${AUDIT_BUCKET}/${AUDIT_PATH}/"

fi
