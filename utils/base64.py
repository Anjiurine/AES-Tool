import base64

def base64_encode(data):
    return base64.b64encode(data).decode('utf-8')

def base64_decode(data):
    return base64.b64decode(data.encode('utf-8'))
