package OrToAnd;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

public class ReqHandle implements HttpHandler {
    private final MontoyaApi api;

    private static final List<String> TOKENS = List.of(
            " or", "+or+", "%20or%20", " OR", "+OR+", "%20OR%20"
    );

    public ReqHandle(MontoyaApi api) {
        this.api = api;
    }

    private static final class MatchPosition {
        final int start;
        final int end;
        final String token;

        MatchPosition(int start, int end, String token) {
            this.start = start;
            this.end = end;
            this.token = token;
        }
    }

    private List<MatchPosition> findPositions(ByteArray requestBytes,
List<String> elements) {
        List<MatchPosition> positions = new ArrayList<>();
        for (String element : elements) {
            int offset = 0;
            while (offset < requestBytes.length()) {
                int start = requestBytes.indexOf(element, true, offset,
requestBytes.length());
                if (start == -1) {
                    break;
                }
                int end = start +
element.getBytes(StandardCharsets.UTF_8).length;
                positions.add(new MatchPosition(start, end, element));
                offset = end;
            }
        }
        positions.sort(Comparator.comparingInt(position -> position.start));
        return positions;
    }

    @Override
    public RequestToBeSentAction
handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        ToolType toolType = requestToBeSent.toolSource().toolType();
        if (toolType != ToolType.SCANNER && toolType !=
ToolType.EXTENSIONS) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        int messageId = requestToBeSent.messageId();
        ByteArray requestBytes = requestToBeSent.toByteArray().copy();
        List<MatchPosition> positions = findPositions(requestBytes, TOKENS);
        if (positions.isEmpty()) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        int offsetShift = 0;
        for (MatchPosition position : positions) {
            api.logging().logToOutput(
                    "---Detected SQL OR clause \"" + position.token + "\" in [" + messageId + "]"
            );

            int start = position.start + offsetShift;
            int end = position.end + offsetShift;
            String replacement = position.token.matches(".*[A-Z].*")
                    ? position.token.replaceAll("(?i)or", "AND")
                    : position.token.replaceAll("(?i)or", "and");

            ByteArray prefix = requestBytes.subArray(0, start);
            ByteArray replacementBytes = ByteArray.byteArray(replacement);
            ByteArray suffix = end < requestBytes.length()
                    ? requestBytes.subArray(end, requestBytes.length())
                    : ByteArray.byteArray("");
            requestBytes =
prefix.withAppended(replacementBytes).withAppended(suffix);
            offsetShift += replacementBytes.length() - (end - start);
        }

        int headerBodySeparator = requestBytes.indexOf("\r\n\r\n", true, 0,
requestBytes.length());
        int bodyStart = headerBodySeparator < 0 ? requestBytes.length() :
headerBodySeparator + 4;
        HttpRequest modifiedRequest =
HttpRequest.httpRequest(requestToBeSent.httpService(), requestBytes);
        if (bodyStart < requestBytes.length()) {
            ByteArray body = requestBytes.subArray(bodyStart,
requestBytes.length());
            modifiedRequest = modifiedRequest.withBody(body);
        }
        return RequestToBeSentAction.continueWith(modifiedRequest);
    }

    @Override
    public ResponseReceivedAction
handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }
}