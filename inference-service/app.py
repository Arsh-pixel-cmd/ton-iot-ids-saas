
from io import BytesIO
from pathlib import Path

import joblib
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile

APP_DIR = Path(__file__).resolve().parent
BUNDLE_PATH = APP_DIR / "ton_iot_production_bundle.joblib"

bundle = joblib.load(BUNDLE_PATH)

app = FastAPI(
    title="ToN-IoT Intrusion Detection API",
    version=bundle["model_version"]
)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_version": bundle["model_version"],
        "required_input_columns": len(
            bundle["required_input_columns"]
        ),
        "decision_threshold": bundle["threshold"]
    }


@app.post("/predict")
async def predict(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a CSV file."
        )

    raw_bytes = await file.read()

    # Simple MVP safety limit: reject very large uploads.
    if len(raw_bytes) > 25 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="CSV file is larger than the 25 MB MVP limit."
        )

    try:
        input_dataframe = pd.read_csv(BytesIO(raw_bytes))
    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Could not parse CSV: {error}"
        )

    missing_columns = [
        column
        for column in bundle["required_input_columns"]
        if column not in input_dataframe.columns
    ]

    if missing_columns:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Input schema is missing required columns.",
                "missing_columns": missing_columns
            }
        )

    try:
        raw_features = input_dataframe[
            bundle["required_input_columns"]
        ].copy()
        transformed_features = bundle["preprocessor"].transform(
            raw_features
        )
        probabilities = bundle["model"].predict_proba(
            transformed_features
        )[:, 1]
        predictions = (
            probabilities >= bundle["threshold"]
        ).astype(int)
    except Exception as error:
        raise HTTPException(
            status_code=422,
            detail=f"Could not transform or score records: {error}"
        )

    output = input_dataframe.copy()
    output["prediction"] = predictions
    output["prediction_name"] = output["prediction"].map({
        0: "normal",
        1: "attack"
    })
    output["probability_attack"] = probabilities
    output["model_version"] = bundle["model_version"]

    return {
        "model_version": bundle["model_version"],
        "decision_threshold": bundle["threshold"],
        "rows_processed": len(output),
        "prediction_counts": {
            "normal": int((predictions == 0).sum()),
            "attack": int((predictions == 1).sum())
        },
        "results": output.to_dict(orient="records")
    }
