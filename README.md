# URLinfo

- Analyzing HTTP headers: Es prüft, ob wichtige Sicherheits-Header wie X-Frame-Options, Content-Security-Policy, Strict-Transport-Security und X-Content-Type-Options in den HTTP-Headern der Website vorhanden sind, und meldet, wenn sie fehlen.

- Finding links: Es durchsucht die Webseite nach internen und externen Links und überprüft, ob diese gültig sind oder zu "broken" (defekten) Seiten führen.

- Detecting technologies: Es versucht, durch die HTTP-Header Technologien zu erkennen, die auf der Webseite verwendet werden (z. B. welche Software sie betreibt).

- Scanning for common directories: Es prüft, ob häufige Verzeichnisse wie /admin, /login, /backup auf der Website existieren, was potenziell gefährliche Bereiche anzeigt.

- pip install requests beautifulsoup4
