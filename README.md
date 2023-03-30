# WebAuthn Playground

Developer testing tools for WebAuthn operations.

## Objective and context

This application helps to visualize the [WebAuthn](https://www.w3.org/TR/webauthn-3/) behavior and responses on the different platforms/browsers.

The tool can be configured to use either the [SimpleWebAuthn](https://simplewebauthn.dev/) browser library, or the [Thales IdCloud](https://developer.dbp.thalescloud.io/docs/idcloud-getting-started) library. The behavior is expected to be similar in both configurations.

This is a **client-only tool**: there is no server involved.
## Usage

* Register (create credential) and Login (get credential) operations can be configured with dropdown / checkbox settings, the JSON request is automatically updated and displayed
* The displayed JSON request can further be customized manually in the "input" text area. This area turns to red when JSON is invalid. You can reset to default JSON by clicking the sponge icon.
* The result of the WebAuthn operation is displayed in the "output" text area. Some useful encoded parts from the WebAuthn response are automatically decoded in a human-readable format below the "output" area.
* You can also paste your own WebAuthn json response obtained elsewhere, and click the magnifier icon to parse it. Note that the parser expects the bytes buffers to be base64 encoded in the JSON.

