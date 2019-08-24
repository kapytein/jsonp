from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IExtensionHelpers
from java.net import URL
from array import array
from urlparse import urlparse
import sys
import os

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("jsonp")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

    def load_payloads(self):  
        lines = []
        with open('payloads.txt') as f:
            lines = f.read().splitlines()

        return lines

    '''
    https://stackoverflow.com/questions/3675318/how-to-replace-the-some-characters-from-the-end-of-a-string
    '''
    def replace_last(self, source_string, replace_what, replace_with):
        head, _sep, tail = source_string.rpartition(replace_what)
        return head + replace_with + tail

    def remove_parameters(self, url):
        u = urlparse(url)
        query = "?" + u.query
        return url.replace(query, '')

    '''
    The function attempts to place the payload within the requested URL. A payload consists of an extension and query parameters only.
    URL's end often (without query parameters / fragment) with a slash (/) or without a slash. Both scenarios are currently covered by this function. 
    '''
    def construct_url(self, url, payload):
        has_slash = False
        org_url = urlparse(url)

        url = self.remove_parameters(url)
     
        if url.endswith("/"):
            has_slash = True
            url = self.replace_last(url, '/', '')

        u = urlparse(url)
        url_ext = os.path.splitext(u.path)[1]
        payload_ext = urlparse(payload)

        # we have an ext in the payload
        if payload_ext.path != "": 
            if url_ext != "":
                url = self.replace_last(url, url_ext, payload_ext.path)
                payload = payload.replace(payload_ext.path, '')
   
            elif has_slash == True and url_ext == "":
                # place payload ext before the /
                url = url + payload_ext.path
                payload = payload.replace(payload_ext.path, '')

        if has_slash == True:
            url = url + "/"

        if org_url.query != "":
            if payload_ext.query != "":
                payload = payload + "&" + org_url.query
            else:
                payload = payload + "?" + org_url.query

        return url + payload

    def replace_header(self, headers, value):
        # the request method will always be the first value in the list
        headers[0] = value 
        return headers

    def doPassiveScan(self, baseRequestResponse):
        response = baseRequestResponse.getResponse()

        res_type = self._helpers.analyzeResponse(response).getStatedMimeType()
        if res_type == "JSON":
            payloads = self.load_payloads()

            for i in payloads:
                request_url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
                payload_url = urlparse(self.construct_url(str(request_url), i))
                
                if payload_url.query != "":
                    payload_format = '{uri.path}?{uri.query}'.format(uri=payload_url)
                else:
                    payload_format = '{uri.path}'.format(uri=payload_url)

                request_headers = self.replace_header(self._helpers.analyzeRequest(baseRequestResponse).getHeaders(), "GET " + payload_format + " HTTP/1.1")

                request = self._helpers.buildHttpMessage(request_headers, None)
                print("Edited URL, and creating request to the following URL: " + payload_format)

                response = self._callbacks.makeHttpRequest(request_url.getHost(), request_url.getPort(), False if request_url.getProtocol() == "http" else True, request)
                response_type = self._helpers.analyzeResponse(response).getStatedMimeType()

                if response_type == "script":
                    
                    return [CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [baseRequestResponse],
                        "Hidden JSONP endpoint found",
                        # @TODO A class which implements IHttpRequestResponse needs to be created for a byte > ihttprequestresponse conversion. There's no helper for this
                        "Callback request path: " + payload_format + ". A JSON endpoint was found with a (possibly hidden) JSONP functionality. This allows you to retrieve the returned data cross-origin (in case there are no additional checks / CSRF tokens in place). This may also help to bypass content security policies.",
                        "Medium")]

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
 
        return 0

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService