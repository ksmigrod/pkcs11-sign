package pl.gov.mofnet.giif.spikes.pkcs11sign;

import javax.security.auth.callback.*;
import java.io.Console;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author ksm
 */
public class ConsoleCallbackHandler implements CallbackHandler {

    private static final Logger logger = Logger.getLogger(ConsoleCallbackHandler.class.getName());

    public ConsoleCallbackHandler() {
        if (System.console() == null) {
            throw new UnsupportedOperationException("Console not available.");
        }
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        Console con = System.console();
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                PasswordCallback pc = (PasswordCallback) callback;
                String prompt = pc.getPrompt();
                prompt = prompt != null && ! prompt.isEmpty() ? prompt : "PIN";
                con.format("%s: ", prompt);
                logger.log(Level.INFO,
                        "Password callback with prompt: {0}",
                        prompt);
                char[] password = con.readPassword();
                pc.setPassword(password);
            } else if (callback instanceof TextOutputCallback) {
                TextOutputCallback tc = (TextOutputCallback) callback;
                con.format("%s", tc.getMessage());
                logger.log(Level.INFO,
                        "TextOutputCallback type {0} message: {1}",
                        new Object[]{tc.getMessageType(), tc.getMessage()});
            } else if (callback instanceof NameCallback) {
                NameCallback nc = (NameCallback) callback;
                String prompt = nc.getPrompt();
                prompt = prompt != null && ! prompt.isEmpty() ? prompt : "Name";
                String defaultName = nc.getDefaultName();
                if (defaultName != null && ! defaultName.isEmpty()) {

                }
            } else {
                logger.log(Level.WARNING,
                        "Unknown callback type {0}",
                        callback.getClass().getName());
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

}