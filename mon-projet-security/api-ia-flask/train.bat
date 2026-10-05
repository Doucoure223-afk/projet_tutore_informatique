@echo off
cd /d "%~dp0"
echo Installation des dependances...
pip install -q scikit-learn numpy joblib
if errorlevel 1 (
    echo Echec: pip install
    pause
    exit /b 1
)
echo.
echo Entrainement du modele ML...
python train_model.py
if errorlevel 1 (
    echo Echec: train_model.py
    pause
    exit /b 1
)
echo.
echo Termine. model.joblib a ete cree.
pause
