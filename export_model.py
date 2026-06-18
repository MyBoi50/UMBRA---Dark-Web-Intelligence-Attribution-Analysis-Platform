# export_model.py
import os
import pickle
import numpy as np
from pathlib import Path

# --- Adjust these imports to match names in your qml.py ---
# qml.py must expose variables or functions that end up with:
# scaler (sklearn StandardScaler), pca (PCA), theta_trained (numpy array / circuit params),
# best_thr (float), pca_n_components (int) and the function to run the quantum circuit returning probabilities.
#
# If qml.py does not provide them as globals, add code there to store/return them.

import qml  # your existing file

OUT = Path("model_artifacts")
OUT.mkdir(exist_ok=True)

# 1) Save scaler
if hasattr(qml, "scaler"):
    with open(OUT / "scaler.pkl", "wb") as f:
        pickle.dump(qml.scaler, f)
    print("Saved scaler")
else:
    print("Warning: qml.scaler not found. You may need to assign scaler in qml.py")

# 2) Save PCA
if hasattr(qml, "pca"):
    with open(OUT / "pca.pkl", "wb") as f:
        pickle.dump(qml.pca, f)
    print("Saved PCA")
else:
    print("Warning: qml.pca not found. If no PCA used, that's fine.")

# 3) Save trained circuit weights (theta) / parameters
# Common variable names might be: theta, weights, params, opt_weights
for candidate in ("theta_trained", "theta", "weights", "opt_weights", "params"):
    if hasattr(qml, candidate):
        theta = getattr(qml, candidate)
        np.save(OUT / "circuit_theta.npy", np.array(theta))
        print(f"Saved circuit params from qml.{candidate}")
        break
else:
    print("Warning: no circuit params found in qml.py (theta).")

# 4) Save best threshold
if hasattr(qml, "best_thr"):
    with open(OUT / "best_thr.pkl", "wb") as f:
        pickle.dump(float(qml.best_thr), f)
    print("Saved best threshold")
else:
    print("Warning: qml.best_thr not found. You can set it manually later.")

print("Export done. Artifacts in model_artifacts/")
