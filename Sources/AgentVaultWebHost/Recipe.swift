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
