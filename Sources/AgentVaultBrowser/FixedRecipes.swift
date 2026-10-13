import Foundation
import WebKit

/// The only file allowed to run JavaScript in a page (enforced by SourceInvariantTests).
///
/// Every recipe is a constant function body. Values reach the page as typed
/// `callAsyncJavaScript` arguments, never by string interpolation, and no recipe accepts
/// script text from a caller, a tool request or a page. Recipes run in a private content
/// world and call WebKit prototype methods directly, so page-defined names on the form
/// or document (DOM clobbering) cannot redirect them.
@MainActor
struct FixedRecipes {
    private static let world = WKContentWorld.world(name: "agentvault.fixed-recipes")

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
        if (destination.origin !== origin) return "form";
        if (getMethod.call(form).toLowerCase() !== "post") return "form";
        const target = getTarget.call(form);
        if (target !== "" && target !== "_self") return "form";
        """

    private static let fillBody = findForm + """

        const users = sub.call(form, userSel);
        const passwords = sub.call(form, passSel);
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

    private static let submitBody = findForm + """

        const buttons = sub.call(form, submitSel);
        if (buttons.length !== 1) return "fields";
        HTMLFormElement.prototype.requestSubmit.call(form, buttons[0]);
        return "ok";
        """

    private static let presenceBody = """
        if (window.location.origin !== origin) return false;
        return Document.prototype.querySelector.call(document, selector) !== null;
        """

    private static let profileBody = """
        if (window.location.origin !== origin) return null;
        const all = Document.prototype.querySelectorAll;
        const getAttr = Element.prototype.getAttribute;
        const logins = all.call(document, loginSel), ids = all.call(document, idSel);
        if (logins.length !== 1 || ids.length > 1) return null;
        return { login: getAttr.call(logins[0], "content"),
                 id: ids.length === 1 ? getAttr.call(ids[0], "content") : null };
        """

    enum LoginResult: String { case ok, origin, form, fields }

    let webView: WKWebView
    let origin: WebOrigin
    let definition: WorkflowDefinition

    private func call(_ body: String, _ arguments: [String: Any]) async -> Any? {
        try? await webView.callAsyncJavaScript(body, arguments: arguments, in: nil, contentWorld: Self.world)
    }

    private var formArguments: [String: Any] {
        ["origin": origin.serialized, "formSel": definition.formSelector,
         "userSel": definition.usernameSelector, "passSel": definition.passwordSelector,
         "submitSel": definition.submitSelector]
    }

    func fill(_ credential: WebCredential) async -> LoginResult {
        var arguments = formArguments
        arguments["username"] = credential.username
        arguments["password"] = credential.password
        return (await call(Self.fillBody, arguments) as? String).flatMap(LoginResult.init) ?? .fields
    }

    func submit() async -> LoginResult {
        (await call(Self.submitBody, formArguments) as? String).flatMap(LoginResult.init) ?? .fields
    }

    func containsCaptcha() async -> Bool { await contains(definition.captchaSelector) }

    func containsLoginForm() async -> Bool { await contains(definition.formSelector) }

    private func contains(_ selector: String) async -> Bool {
        await call(Self.presenceBody, ["origin": origin.serialized, "selector": selector]) as? Bool ?? false
    }

    /// Returns validated, typed values only. Nothing else about the page leaves this function.
    func readProfile() async -> WebProfile? {
        let arguments: [String: Any] = ["origin": origin.serialized, "loginSel": definition.profileLoginSelector,
                                        "idSel": definition.profileIDSelector]
        guard let raw = await call(Self.profileBody, arguments) as? [String: Any],
              let login = raw["login"] as? String,
              login.range(of: "^[A-Za-z0-9][A-Za-z0-9-]{0,38}$", options: .regularExpression) != nil
        else { return nil }
        var userID: Int?
        if let text = raw["id"] as? String {
            guard text.count <= 12, let value = Int(text), value > 0 else { return nil }
            userID = value
        }
        return WebProfile(login: login, userID: userID)
    }
}
