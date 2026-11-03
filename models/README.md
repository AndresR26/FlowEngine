# models/

🇪🇸 Aquí va `modelo_rf_ids.joblib` **solo en tu copia local**. No se sube al repositorio (`.gitignore`) porque suele ser grande y depende de la versión de scikit-learn.
Publícalo como adjunto en **GitHub → Releases** o con **Git LFS** (`git lfs track "*.joblib"`).
Para usarlo, cópialo **junto a `FlowEngine.exe`** (y junto al de cada agente).
Requisitos: entrenado con un `pandas.DataFrame` (expone `feature_names_in_`) y con los nombres de columna que genera FlowEngine. Ver manual técnico §9.

🇬🇧 `modelo_rf_ids.joblib` goes here **in your local copy only**. It is not committed (`.gitignore`) because it is usually large and tied to a scikit-learn version.
Publish it as an asset in **GitHub → Releases** or with **Git LFS** (`git lfs track "*.joblib"`).
To use it, copy it **next to `FlowEngine.exe`** (and next to each agent's copy).
Requirements: trained on a `pandas.DataFrame` (exposes `feature_names_in_`) using FlowEngine's column names. See technical manual §9.
