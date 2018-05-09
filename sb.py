import urllib

def safebrowse(target_url, check_reason):
    """This will submit the URL to Google Safe browsing. Since they have Captcha
    protection on the page, you'll need to manually visit this URL. It should
    autopopulate what it can through the url."""
    enc_url = urllib.parse.quote_plus(target_url)
    enc_reason = urllib.parse.quote_plus(check_reason)
    print('Click the URL below, it should autopopulate the fields. Complete '\
        'the captcha and submit to report the site to Google Safe Browsing.')
    submit = 'https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en&url=' + enc_url + '&dq=' + enc_reason
    return submit