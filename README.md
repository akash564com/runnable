gamezone/                         # Main project root
│
├── app.py                        # Flask backend (Firebase Auth, Games, Admin Panel, Premium logic)
├── requirements.txt               # Python dependencies
├── .render.yaml                    # Render deployment config
├── .gitignore                      # Ignore cache, DB, env, etc.
├── games.db                       # SQLite DB (auto-created if not exists)
├── README.md                      # Documentation
│
├── templates/                     # HTML Templates
│   ├── index.html                 # Main homepage (user login, games list)
│   ├── login.html                 # Firebase login UI (Google + Email)
│   ├── signup.html                # Sign-up page (Firebase Email/Pass)
│   ├── forgot_password.html       # Reset password UI
│   ├── admin.html                 # Admin panel (upload games, auto/draft, preview)
│   ├── play.html                  # Game player page (embedded games)
│   └── support.html               # AI support chat page
│
├── static/                        # Static assets
│   ├── styles.css                 # Main CSS (dark neon 3D style)
│   ├── admin.css                  # Admin-specific styles
│   ├── script.js                  # Common frontend scripts
│   ├── admin.js                   # Admin-specific JS (upload handling, previews)
│   ├── firebase-config.js         # Firebase client config for frontend auth
│   ├── uploads/                   # Unzipped uploaded games (public play)
│   ├── game_zips/                 # Original .zip game uploads (for storage)
│   ├── game_thumbs/               # Uploaded game thumbnails
│   └── assets/                    # Images, icons, fonts
│
└── .env                           # Environment variables (never commit)
