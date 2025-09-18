import os, time, hmac, hashlib, json, requests
def sumsub_generate_sdk_token(user_external_id, email=None, phone=None):
    base = os.getenv('SUMSUB_API_URL','https://api.sumsub.com')
    url = base.rstrip('/') + '/resources/accessTokens/sdk'
    ts = str(int(time.time()))
    body = {'applicantIdentifiers': {}, 'ttlInSecs': int(os.getenv('SUMSUB_TTL_SECS','600')), 'userId': str(user_external_id), 'levelName': os.getenv('SUMSUB_LEVEL_NAME','basic-kyc-level')}
    if email: body['applicantIdentifiers']['email'] = email
    if phone: body['applicantIdentifiers']['phone'] = phone
    body_str = json.dumps(body, separators=(',',':'))
    method = 'POST'; uri = '/resources/accessTokens/sdk'
    to_sign = ts + method + uri + body_str
    secret = os.getenv('SUMSUB_SECRET_KEY','').encode('utf-8')
    sig = hmac.new(secret, to_sign.encode('utf-8'), hashlib.sha256).hexdigest().lower()
    headers = {'Content-Type':'application/json','X-App-Token': os.getenv('SUMSUB_APP_TOKEN',''),'X-App-Access-Ts': ts,'X-App-Access-Sig': sig}
    resp = requests.post(url, headers=headers, data=body_str, timeout=10); resp.raise_for_status(); return resp.json()
def sumsub_verify_webhook(raw_body_bytes, headers):
    alg = headers.get('X-Payload-Digest-Alg') or headers.get('x-payload-digest-alg','HMAC_SHA256_HEX'); digest_header = headers.get('X-Payload-Digest') or headers.get('x-payload-digest',''); secret = os.getenv('SUMSUB_WEBHOOK_SECRET','').encode('utf-8')
    if alg.upper() == 'HMAC_SHA256_HEX': computed = hmac.new(secret, raw_body_bytes, hashlib.sha256).hexdigest()
    elif alg.upper() == 'HMAC_SHA512_HEX': computed = hmac.new(secret, raw_body_bytes, hashlib.sha512).hexdigest()
    else: computed = hmac.new(secret, raw_body_bytes, hashlib.sha1).hexdigest()
    return computed == digest_header.lower().strip()
def veriff_create_session(user_external_id, first_name=None, last_name=None, callback_url=None):
    base = os.getenv('VERIFF_BASE_URL','https://api.veriff.com'); url = base.rstrip('/') + '/v1/sessions'
    headers = {'Content-Type':'application/json','X-AUTH-CLIENT': os.getenv('VERIFF_API_KEY','')}
    body = {'verification': {}}
    if callback_url: body['verification']['callback'] = callback_url
    body['verification']['vendorData'] = str(user_external_id)
    if first_name or last_name:
        body['person'] = {}
        if first_name: body['person']['firstName'] = first_name
        if last_name: body['person']['lastName'] = last_name
    resp = requests.post(url, headers=headers, json=body, timeout=10); resp.raise_for_status(); return resp.json()
def veriff_verify_webhook(raw_body_bytes, headers):
    sig_header = headers.get('X-HMAC-SIGNATURE') or headers.get('x-hmac-signature',''); secret = os.getenv('VERIFF_SHARED_SECRET','').encode('utf-8')
    computed = hmac.new(secret, raw_body_bytes, hashlib.sha256).hexdigest()
    return computed == sig_header.lower().strip()
