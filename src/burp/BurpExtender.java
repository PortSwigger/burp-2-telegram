package burp;

import java.awt.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.*;
import java.io.PrintWriter;
import java.util.Timer;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener{
    IBurpExtenderCallbacks callbacks;
    IHttpRequestResponsePersisted PerRequestResponse;
    IExtensionHelpers helpers;

    protected String mPluginName = "Burp2Telegram";


    public String token;
    public String chat;
    private final List<LogRequestResponse> log = new ArrayList<LogRequestResponse>();
    public String getCurrentPayload;
    public static Timer timer;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        BurpExtenderTab.callbacks = callbacks;

        callbacks.setExtensionName("Burp2Telegram Extension");
        callbacks.printOutput("Burp2Telegram 1.0 loaded");

        BurpExtenderTab.configcomp = new ConfigComponent(callbacks);

        callbacks.registerHttpListener(this);
        callbacks.addSuiteTab(this);
        
        BurpExtenderTab.configcomp.telegramTokentxtbox.setText(callbacks.loadExtensionSetting("token_bot_telegram"));
        BurpExtenderTab.configcomp.chatIDtxtbox.setText(callbacks.loadExtensionSetting("chat_id_telegram"));

        if (callbacks.loadExtensionSetting("notification_message_telegram").equals("")){
            BurpExtenderTab.configcomp.msgformattxtbox.setText("*[Burp]* Matched the condition: *{{FOUND}}* in Response: `{{BODY}}`");
        } else {
            BurpExtenderTab.configcomp.msgformattxtbox.setText(callbacks.loadExtensionSetting("notification_message_telegram"));
        }
    }


    @Override
    public String getTabCaption() {
        return BurpExtenderTab.tabName;
    }

    @Override
    public Component getUiComponent() {
        return BurpExtenderTab.configcomp.$$$getRootComponent$$$();
    }


    public void pushMessage(){
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        this.token = BurpExtenderTab.configcomp.telegramTokentxtbox.getText().toString();
        this.chat = BurpExtenderTab.configcomp.chatIDtxtbox.getText().toString();

        try {
            URL url = new URL("https://api.telegram.org/bot" + token + "/sendMessage");
            String data = "disable_web_page_preview=true&parse_mode=markdown&" + "chat_id=" + chat + "&text=" + callbacks.getHelpers().urlEncode(getCurrentPayload);

            List<String> headers = new ArrayList<>();
            headers.add("POST " + url.getPath() + " HTTP/2");
            headers.add("Host: " + url.getHost());
            headers.add("User-Agent: Burp2Telegram/1.0");
            headers.add("Content-Type: application/x-www-form-urlencoded");
            headers.add("Content-Length: " + data.length());

            byte[] builder = callbacks.getHelpers().buildHttpMessage(headers, data.getBytes());
            byte[] responseBytes = callbacks.makeHttpRequest(url.getHost(), 443,true, builder,false);

        } catch (MalformedURLException e1) {
            stdout.println(e1);
        } catch (Exception ge) {
            stdout.println(ge);
        }
    }




    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        //stdout.println("" + this.callbacks.isInScope(this.callbacks.getHelpers().analyzeRequest(messageInfo).getUrl()));

        boolean flag = false;

        if (BurpExtenderTab.configcomp.onlyInScopeCheckBox.isSelected() && this.callbacks.isInScope(this.callbacks.getHelpers().analyzeRequest(messageInfo).getUrl())){
            flag = true;
        }
        if (BurpExtenderTab.configcomp.extenderCheckBox.isSelected() && toolFlag == callbacks.TOOL_EXTENDER){
            flag = true;
        }
        if (BurpExtenderTab.configcomp.intruderCheckBox.isSelected() && toolFlag == callbacks.TOOL_INTRUDER){
            flag = true;
        }
        if (BurpExtenderTab.configcomp.proxyCheckBox.isSelected() && toolFlag == callbacks.TOOL_PROXY){
            flag = true;
        }
        if (BurpExtenderTab.configcomp.repeaterCheckBox.isSelected() && toolFlag == callbacks.TOOL_REPEATER){
            flag = true;
        }
        if (BurpExtenderTab.configcomp.scannerCheckBox.isSelected() && toolFlag == callbacks.TOOL_SCANNER){
            flag = true;
        }
        if (BurpExtenderTab.configcomp.spiderCheckBox.isSelected() && toolFlag == callbacks.TOOL_SPIDER){
            flag = true;
        }
        if (BurpExtenderTab.configcomp.targetCheckBox.isSelected() && toolFlag == callbacks.TOOL_TARGET){
            flag = true;
        }

        this.callbacks.saveBuffersToTempFiles(messageInfo);

        if (flag){
            log.add(new LogRequestResponse(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo), messageIsRequest));
        }

        int getPollSeconds = Integer.parseInt(BurpExtenderTab.configcomp.pollseconds.getText().toString());

        if (VariableManager.getisStart()) {
            timer = new Timer("Timer");
            TimerTask task = new TimerTask() {
                public void run() {

                    Match2Telegram();

                }
            };


            timer.schedule(task, 1000, getPollSeconds);
            VariableManager.setisStart(false);
        }


    }

    public void Match2Telegram() {
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);

        // Loop through the saved Requests/Responses
        if (log.size() > 0) {
            for (int i = 0; i < log.size(); i++) {
                if (!log.get(i).messageIsRequest) {
                    IResponseInfo res = callbacks.getHelpers().analyzeResponse(log.get(i).requestResponse.getResponse());

                    // Parse Intruder Response
                    int responseStatusCode = res.getStatusCode();
                    ArrayList<String> responseHeaders = new ArrayList<>(res.getHeaders());


                    int bodyOffset = res.getBodyOffset();
                    byte[] byte_Request = log.get(i).requestResponse.getResponse();
                    byte[] byte_body = Arrays.copyOfRange(byte_Request, bodyOffset, byte_Request.length);

                    String responseBody = callbacks.getHelpers().bytesToString(byte_body);
                    responseBody = this.callbacks.getHelpers().urlEncode(responseBody).toString();


                    // Get response body textbox Index
                    int checkbody = responseBody.indexOf(BurpExtenderTab.configcomp.responsebodycontainstxtbox.getText().toString());
                    String responseBodyInput = BurpExtenderTab.configcomp.responsebodycontainstxtbox.getText().toString().replace("\"", "\\\"");

                    // Replace {{BODY}} with the following string. 100 chars before and after (to just focus on the matched payload).
                    String getBody = "";
                    int margin = 3500;
                    if (checkbody != -1 ) {
                        if (checkbody > margin) {
                            if (checkbody + margin > responseBody.length()) {
                                getBody = responseBody.substring(checkbody - margin, responseBody.length());
                            } else {
                                getBody = responseBody.substring(checkbody - margin, checkbody + margin);
                            }
                        } else {
                            if(checkbody - margin < 0 && responseBody.length() > margin){
                            getBody = responseBody.substring(0, checkbody + margin);
                            }else{
                                getBody = responseBody.substring(0, responseBody.length());
                            }
                        }

                    }

                    int responseContentLength = responseBody.length();

                        // Checking IF {body contains}
                        if (BurpExtenderTab.configcomp.responsebodycontainstxtbox.getText().toString().length() > 0) {
                            if (checkbody!=-1) {
                                this.getCurrentPayload = BurpExtenderTab.configcomp.msgformattxtbox.getText().toString().replace("{{FOUND}}",responseBodyInput);
                                this.getCurrentPayload = this.getCurrentPayload.replace("{{BODY}}", getBody);

                                pushMessage();


                            }
                        }

                        // Check Status Code
                        if (BurpExtenderTab.configcomp.httpstatuscodetxtbox.getText().toString().length() > 0) {
                            if (responseStatusCode == Integer.parseInt(BurpExtenderTab.configcomp.httpstatuscodetxtbox.getText().toString())

                            ) {
                                this.getCurrentPayload = BurpExtenderTab.configcomp.msgformattxtbox.getText().toString().replace("{{FOUND}}",
                                        " " + responseStatusCode);
                                this.getCurrentPayload = this.getCurrentPayload.replace("{{BODY}}", getBody);


                                pushMessage();


                            }
                        }

                        // Check Headers
                        if (BurpExtenderTab.configcomp.responseheaderscontaintxtbox.getText().toString().length() > 0) {
                            for (int ii = 0; ii < responseHeaders.size(); ii++) {

                                if (responseHeaders.get(ii).toString().contains(BurpExtenderTab.configcomp.responseheaderscontaintxtbox.getText().toString())
                                ) {

                                    this.getCurrentPayload = BurpExtenderTab.configcomp.msgformattxtbox.getText().toString().replace("{{FOUND}}",
                                            responseHeaders.get(ii).toString().replace("\"", "\\\""));
                                    this.getCurrentPayload = this.getCurrentPayload.replace("{{BODY}}", responseHeaders.get(ii).toString().replace("\"", "\\\""));

                                    pushMessage();

                                    ii = responseHeaders.size();


                                }

                            }
                        }

                        // Check Response Length
                        if (BurpExtenderTab.configcomp.contentlengthtxtbox.getText().toString().length() > 0) {
                            String contentlength = BurpExtenderTab.configcomp.contentlengthtxtbox.getText().toString();
                            char operator = contentlength.charAt(0);
                            int targetlength = Integer.parseInt(contentlength.substring(2, contentlength.length()));
                            switch (operator) {
                                case '>': {

                                    if (responseContentLength > targetlength) {
                                        this.getCurrentPayload = BurpExtenderTab.configcomp.msgformattxtbox.getText().toString().replace("{{FOUND}}",
                                                " > " + targetlength);
                                        this.getCurrentPayload = this.getCurrentPayload.replace("{{BODY}}", getBody);

                                        pushMessage();

                                    }
                                    break;
                                }
                                case '<': {
                                    if (responseContentLength < targetlength) {
                                        this.getCurrentPayload = BurpExtenderTab.configcomp.msgformattxtbox.getText().toString().replace("{{FOUND}}",
                                                " < " + targetlength);
                                        this.getCurrentPayload = this.getCurrentPayload.replace("{{BODY}}", getBody);

                                        pushMessage();

                                    }
                                    break;
                                }
                                case '=': {
                                    if (responseContentLength == targetlength) {
                                        this.getCurrentPayload = BurpExtenderTab.configcomp.msgformattxtbox.getText().toString().replace("{{FOUND}}",
                                                " == " + targetlength);
                                        this.getCurrentPayload = this.getCurrentPayload.replace("{{BODY}}", getBody);

                                        pushMessage();

                                    }
                                    break;
                                }
                                case '!': {
                                    if (responseContentLength != targetlength) {
                                        this.getCurrentPayload = BurpExtenderTab.configcomp.msgformattxtbox.getText().toString().replace("{{FOUND}}",
                                                " != " + targetlength);
                                        this.getCurrentPayload = this.getCurrentPayload.replace("{{BODY}}", getBody);

                                        pushMessage();

                                    }
                                    break;
                                }

                            }
                        }

                    }


                }



            //Clear
            log.clear();
        }

        if (!VariableManager.getisStart() && VariableManager.getstopTimer()) {
            timer.cancel();
            timer.purge();
        }


    }
}
