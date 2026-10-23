import AgentVaultWebHostProtocol
import Foundation

/// The only page scripts the host can run. Each body is a constant function declaration; values
/// reach it as typed `Runtime.callFunctionOn` arguments, never by string interpolation. They run
/// in an isolated world and call DOM prototype methods directly, so page-defined names on the
/// form or document (DOM clobbering) cannot redirect them. Ported from the reviewed WebKit recipes.
enum Recipe: CaseIterable, Sendable {
    case fill, submit, contains, profile, challengeRect

    private static let findForm = """
        const doc = Document.prototype.querySelectorAll;
        const sub = Element.prototype.querySelectorAll;
        if (window.location.origin !== origin) return "origin";
        const forms = doc.call(document, formSel);
        if (forms.length !== 1) return "fields";
        const form = forms[0];
        const getAction = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, "action").get;
        const getMethod = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, "method").get;
        const getTarget = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, "target").get;
        let destination;
        try { destination = new URL(getAction.call(form), window.location.href); } catch (e) { return "form"; }
        if (destination.origin !== origin || destination.pathname !== actionPath) return "form";
        if (getMethod.call(form).toLowerCase() !== "post") return "form";
        const target = getTarget.call(form);
        if (target !== "" && target !== "_self") return "form";
        """

    /// Argument names, in order, for each recipe.
    var parameters: [String] {
        switch self {
        case .fill: ["origin", "actionPath", "formSel", "userSel", "passSel", "submitSel", "username", "password"]
        case .submit: ["origin", "actionPath", "formSel", "userSel", "passSel", "submitSel"]
        case .contains: ["origin", "selector"]
        case .profile: ["origin", "loginSel", "idSel"]
        case .challengeRect: ["origin", "selector"]
        }
    }

    var body: String {
        switch self {
        case .fill: Self.findForm + """
            const users = sub.call(form, userSel), passwords = sub.call(form, passSel);
            if (users.length !== 1 || passwords.length !== 1) return "fields";
            const user = users[0], pass = passwords[0];
            if (!(user instanceof HTMLInputElement) || !(pass instanceof HTMLInputElement)) return "fields";
            if (pass.type !== "password" || user.type === "password" || user.type === "hidden") return "fields";
            const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
            for (const [element, value] of [[user, username], [pass, password]]) {
                setValue.call(element, value);
                element.dispatchEvent(new Event("input", { bubbles: true }));
                element.dispatchEvent(new Event("change", { bubbles: true }));
            }
            return "ok";
            """
        case .submit: Self.findForm + """
            const buttons = sub.call(form, submitSel);
            if (buttons.length !== 1) return "fields";
            HTMLFormElement.prototype.requestSubmit.call(form, buttons[0]);
            return "ok";
            """
        case .contains: """
            if (window.location.origin !== origin) return false;
            return Document.prototype.querySelector.call(document, selector) !== null;
            """
        case .profile: """
            if (window.location.origin !== origin) return null;
            const all = Document.prototype.querySelectorAll, getAttr = Element.prototype.getAttribute;
            const logins = all.call(document, loginSel), ids = all.call(document, idSel);
            if (logins.length !== 1 || ids.length !== 1) return null;
            return { login: getAttr.call(logins[0], "content"), id: getAttr.call(ids[0], "content") };
            """
        case .challengeRect: """
            if (window.location.origin !== origin) return null;
            const found = Document.prototype.querySelectorAll.call(document, selector);
            if (found.length !== 1) return null;
            const r = Element.prototype.getBoundingClientRect.call(found[0]);
            return { x: r.x, y: r.y, width: r.width, height: r.height,
                     viewWidth: window.innerWidth, viewHeight: window.innerHeight };
            """
        }
    }

    /// `function (origin, ...) { body }` with fixed parameter names.
    var declaration: String { "function (\(parameters.joined(separator: ", "))) {\n\(body)\n}" }
}

/// The only page scripts a continuing-site session runs, in one isolated world per document. That
/// world keeps the document's element table (`__agentVaultTargets`): a target's index means the
/// same element for as long as the document lives, and a page script cannot reach the table. The
/// password field the host filled is remembered (`__agentVaultSecret`) so its value is never
/// observed or typed into, even if the page changes its type. Every recipe first checks that the
/// document is on one of `origins`, which the host passes from the site policy.
enum SiteRecipe: CaseIterable, Sendable {
    case observe, activate, enterText, choose, loginFill, loginSubmit, loginClear, authState

    /// UTF-16 code units of page text one observation may carry out of the page, across all its
    /// strings. Cut inside the recipe, before the browser serializes anything: control characters
    /// are replaced, so each unit is at most 6 bytes of JSON, and the reply stays far below the
    /// shared pipe's `ChromiumPipe.maximumMessageBytes` whatever the page holds.
    static let observationBudget = 1 << 19

    private static let common = """
        if (!Array.prototype.includes.call(origins, window.location.origin)) return "origin";
        const all = Document.prototype.querySelectorAll, sub = Element.prototype.querySelectorAll;
        const rectOf = Element.prototype.getBoundingClientRect, attr = Element.prototype.getAttribute;
        const table = globalThis.__agentVaultTargets || (globalThis.__agentVaultTargets = []);
        const secret = globalThis.__agentVaultSecret || (globalThis.__agentVaultSecret = new WeakSet());
        const shown = (e) => {
            const r = rectOf.call(e);
            if (r.width <= 0 || r.height <= 0) return false;
            const s = window.getComputedStyle(e);
            return s.visibility !== "hidden" && s.display !== "none";
        };
        // Disabled as the page shows it: also by a disabled fieldset or optgroup, which leaves the
        // element's own `disabled` false.
        const disabled = (e) => Element.prototype.matches.call(e, ":disabled");
        const clip = (t, n) => {
            const s = String.prototype.toWellFormed.call(String(t == null ? "" : t))
                .replace(/[\\u0000-\\u001f\\u007f-\\u009f]/g, " ").replace(/\\s+/g, " ").trim();
            if (s.length <= n) return s;
            const cut = s.slice(0, n), last = cut.charCodeAt(cut.length - 1);
            return last >= 0xd800 && last <= 0xdbff ? cut.slice(0, -1) : cut;
        };
        const roleOf = (e) => {
            if (secret.has(e)) return "password";
            const tag = e.localName;
            if (tag === "a") return attr.call(e, "href") === null ? null : "link";
            if (tag === "select") return "select";
            if (tag === "textarea") return "textField";
            if (tag === "button") return e.type === "submit" ? "submit" : "button";
            if (tag === "input") {
                const t = e.type;
                if (t === "password") return "password";
                if (t === "submit" || t === "image") return "submit";
                if (t === "button" || t === "reset") return "button";
                if (t === "checkbox" || t === "radio") return t;
                return ["text", "email", "search", "tel", "url", "number"].includes(t) ? "textField" : null;
            }
            const role = attr.call(e, "role");
            return role === "button" || role === "link" ? role : null;
        };
        """

    /// Resolves `index` to a live, shown, enabled element of one of `roles`, or returns a reason.
    private static let resolve = """
        const e = table[index];
        if (!e || !e.isConnected) return "stale";
        if (!Array.prototype.includes.call(roles, roleOf(e))) return "kind";
        if (disabled(e) || !shown(e)) return "stale";
        """

    private static let loginForm = """
        const passwords = Array.prototype.filter.call(all.call(document, "input"), (e) => e.type === "password" && shown(e));
        if (passwords.length !== 1) return "unsupported";
        const pass = passwords[0];
        const form = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "form").get.call(pass);
        if (!form) return "unsupported";
        const getAction = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, "action").get;
        const getMethod = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, "method").get;
        const getTarget = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, "target").get;
        let destination;
        try { destination = new URL(getAction.call(form), window.location.href); } catch (e) { return "origin"; }
        if (!Array.prototype.includes.call(origins, destination.origin)) return "origin";
        if (getMethod.call(form).toLowerCase() !== "post") return "unsupported";
        const target = getTarget.call(form);
        if (target !== "" && target !== "_self") return "unsupported";
        const users = Array.prototype.filter.call(sub.call(form, "input"),
            (e) => ["text", "email", "tel"].includes(e.type) && shown(e));
        if (users.length !== 1) return "unsupported";
        const user = users[0];
        const buttons = Array.prototype.filter.call(sub.call(form, "button, input"),
            (e) => (e.localName === "button" ? e.type === "submit" : e.type === "submit" || e.type === "image") && shown(e));
        if (buttons.length > 1) return "unsupported";
        // The submit button may send the form elsewhere: its overrides pass the same checks.
        if (buttons.length === 1) {
            const button = buttons[0], has = Element.prototype.hasAttribute;
            const proto = button.localName === "button" ? HTMLButtonElement.prototype : HTMLInputElement.prototype;
            const read = (name) => Object.getOwnPropertyDescriptor(proto, name).get.call(button);
            if (has.call(button, "formaction")) {
                let override;
                try { override = new URL(read("formAction"), window.location.href); } catch (e) { return "origin"; }
                if (!Array.prototype.includes.call(origins, override.origin)) return "origin";
            }
            if (has.call(button, "formmethod") && read("formMethod").toLowerCase() !== "post") return "unsupported";
            if (has.call(button, "formtarget") && read("formTarget") !== "" && read("formTarget") !== "_self") return "unsupported";
        }
        if (target === "" && all.call(document, "base[target]").length > 0) return "unsupported";
        """

    var parameters: [String] {
        switch self {
        case .observe: ["origins"]
        case .activate: ["origins", "index", "roles"]
        case .enterText: ["origins", "index", "roles", "text"]
        case .choose: ["origins", "index", "roles", "option"]
        case .loginFill: ["origins", "username", "password"]
        case .loginSubmit: ["origins"]
        case .loginClear: ["origins"]
        case .authState: ["origins"]
        }
    }

    var body: String {
        switch self {
        case .observe: Self.common + """
            const elements = [], text = [];
            let budget = \(Self.observationBudget);
            const take = (t, n) => { const s = clip(t, Math.min(n, budget)); budget -= s.length; return s; };
            const found = all.call(document, "a, button, input, select, textarea, [role=button], [role=link]");
            for (const e of found) {
                if (elements.length >= \(SiteObservation.maximumElements)) break;
                const role = roleOf(e);
                if (role === null || disabled(e) || !shown(e)) continue;
                let ref = table.indexOf(e);
                if (ref < 0) {
                    if (table.length > \(SiteTarget.maximumElement)) continue;
                    ref = table.push(e) - 1;
                }
                const labels = e.labels && e.labels.length ? e.labels[0].innerText : "";
                const label = attr.call(e, "aria-label") || labels || attr.call(e, "placeholder")
                    || (e.localName === "input" && role !== "textField" && role !== "password" ? e.value : "")
                    || e.innerText || attr.call(e, "title") || attr.call(e, "name") || "";
                let value = "", options = [];
                if (role === "textField") value = e.value;
                else if (role === "checkbox" || role === "radio") value = e.checked ? "checked" : "";
                else if (role === "link") value = e.href;
                else if (role === "select") {
                    options = Array.prototype.slice.call(e.options, 0, \(SiteElement.maximumOptions)).map((o) => take(o.text, 256));
                    value = e.selectedIndex >= 0 && e.options[e.selectedIndex] ? take(e.options[e.selectedIndex].text, 256) : "";
                }
                elements.push({ ref, role, label: take(label, 256), value: role === "password" ? "" : take(value, 1024), options });
            }
            const blocks = all.call(document, "h1, h2, h3, h4, h5, h6, p, li, dt, dd, th, td, caption, legend, pre, blockquote, [role=alert], [role=status]");
            for (const e of blocks) {
                if (text.length >= \(SiteObservation.maximumTextItems)) break;
                if (!shown(e)) continue;
                const t = take(e.innerText, 1024);
                if (t && text[text.length - 1] !== t) text.push(t);
            }
            const password = Array.prototype.some.call(all.call(document, "input"), (e) => (secret.has(e) || e.type === "password") && shown(e));
            return { title: take(document.title, 256), elements, text, password };
            """
        // The effect recipes resolve the element and act on that same element in one synchronous call:
        // no page timer, focus change or replacement can come between the check and the action. They
        // act through the DOM (`click()`, the value setter and input/change events), so the page sees
        // untrusted events (`isTrusted === false`); a site that requires trusted input will not react.
        case .activate: Self.common + Self.resolve + """
            if (!(e instanceof HTMLElement)) return "kind";
            Element.prototype.scrollIntoView.call(e, { block: "center", inline: "center" });
            const r = rectOf.call(e);
            const x = r.x + r.width / 2, y = r.y + r.height / 2;
            if (x < 0 || y < 0 || x >= window.innerWidth || y >= window.innerHeight) return "stale";
            const hit = Document.prototype.elementFromPoint.call(document, x, y);
            if (hit !== e && !Node.prototype.contains.call(e, hit)) return "covered";
            HTMLElement.prototype.click.call(e);
            return "ok";
            """
        case .enterText: Self.common + Self.resolve + """
            if (e.readOnly === true || (e.maxLength >= 0 && text.length > e.maxLength)) return "kind";
            const proto = e.localName === "textarea" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
            Object.getOwnPropertyDescriptor(proto, "value").set.call(e, text);
            e.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertReplacementText", data: text }));
            e.dispatchEvent(new Event("change", { bubbles: true }));
            return "ok";
            """
        case .choose: Self.common + Self.resolve + """
            if (option < 0 || option >= e.options.length || disabled(e.options[option])) return "stale";
            Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "selectedIndex").set.call(e, option);
            e.dispatchEvent(new Event("input", { bubbles: true }));
            e.dispatchEvent(new Event("change", { bubbles: true }));
            return "ok";
            """
        case .loginFill: Self.common + Self.loginForm + """
            const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
            secret.add(pass);
            for (const [element, value] of [[user, username], [pass, password]]) {
                setValue.call(element, value);
                element.dispatchEvent(new Event("input", { bubbles: true }));
                element.dispatchEvent(new Event("change", { bubbles: true }));
            }
            return "ok";
            """
        case .loginSubmit: Self.common + Self.loginForm + """
            if (!secret.has(pass)) return "unsupported";
            if (buttons.length === 1) HTMLFormElement.prototype.requestSubmit.call(form, buttons[0]);
            else HTMLFormElement.prototype.requestSubmit.call(form);
            return "ok";
            """
        case .loginClear: Self.common + """
            const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
            for (const e of all.call(document, "input")) { if (secret.has(e)) setValue.call(e, ""); }
            return "ok";
            """
        case .authState: Self.common + """
            const inputs = all.call(document, "input");
            const password = Array.prototype.some.call(inputs, (e) => e.type === "password" && shown(e));
            const code = Array.prototype.some.call(inputs, (e) => attr.call(e, "autocomplete") === "one-time-code" && shown(e));
            return { password, code };
            """
        }
    }

    var declaration: String { "function (\(parameters.joined(separator: ", "))) {\n\(body)\n}" }
}
