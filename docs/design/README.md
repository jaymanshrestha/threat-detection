# SentinelSMB UI/UX design pack

Open **UI_UX_Design.pdf** - it contains everything in this folder, in order:

1. Purpose of the design (users, UI goal, UX goal, design process, guidance checklist)
2. Information architecture
3. Wireframes - `wireframes/` (greyscale, low fidelity)
4. User flow - `user_flow.png` (wireframes) and `user_flow_hifi.png` (final screens)
5. High-fidelity mockups - `mockups/`
6. Style guide - `style_guide.png`, `styleguide/` (also live in the app at /style-guide)
7. Accessibility - `ACCESSIBILITY.md`
8. Use cases UC-01 … UC-11 and FR-01 … FR-10 → screens, with priority and status - `REQUIREMENTS_MAPPING.md`
9. Differences from the report (Sections 5 and 6) - also in `REQUIREMENTS_MAPPING.md`

`src/` holds the HTML/CSS the wireframes, flow diagrams and PDF are rendered from.
Regenerate with `scripts/design_mockups.py` (needs the app running and an admin login) then `scripts/build_design_docs.py`.
