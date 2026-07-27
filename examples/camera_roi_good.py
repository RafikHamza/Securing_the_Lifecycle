def publish_roi(roi, roi_len):
    status = cpd_verifier_send_roi(roi, roi_len)
    secure_zeroize(roi, roi_len)
    return status
