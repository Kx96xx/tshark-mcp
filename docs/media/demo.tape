# Records docs/media/demo.gif from a live run: `vhs docs/media/demo.tape` from the repository root.
# The client (docs/media/demo_client.py) starts the published PyPI package over stdio and prints
# fields of the real tool results.
Output docs/media/demo.gif
Require uv

Set Shell "bash"
Set FontSize 15
Set Width 1180
Set Height 460
Set Padding 18
Set Framerate 12
Set TypingSpeed 35ms
Set Theme "Catppuccin Mocha"

Hide
Type "export PS1='$ '; clear"
Enter
Show

Type "# Why is there one-way audio on this call? Ask the server over MCP."
Enter
Sleep 600ms
Type "uv run -q --no-project --with mcp python docs/media/demo_client.py"
Sleep 400ms
Enter
Wait+Screen@20s /verdict:/
Sleep 7s
