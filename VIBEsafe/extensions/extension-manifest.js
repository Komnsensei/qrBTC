{
  "manifest_version": 3,
  "name": "vibesafe",
  "version": "0.1.0",
  "description": "The antivirus for vibe-coded projects. Scans AI-generated code for dangerous patterns.",
  "permissions": ["activeTab"],
  "content_scripts": [
    {
      "matches": [
        "https://github.com/*",
        "https://chat.openai.com/*",
        "https://claude.ai/*",
        "https://console.groq.com/*",
        "https://pastebin.com/*",
        "https://gist.github.com/*",
        "https://codepen.io/*"
      ],
      "js": ["vibesafe-core.js", "content.js"],
      "css": ["vibesafe.css"],
      "run_at": "document_idle"
    }
  ],
  "icons": {
    "16": "icons/vibesafe-16.png",
    "48": "icons/vibesafe-48.png",
    "128": "icons/vibesafe-128.png"
  },
  "action": {
    "default_popup": "popup.html",
    "default_icon": "icons/vibesafe-48.png"
  }
}