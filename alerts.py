def generate_alert(risk_level):

    if risk_level == "High":
        return "🚨 High Risk File Detected"

    elif risk_level == "Medium":
        return "⚠️ Medium Risk File Uploaded"

    elif risk_level == "Safe":
        return "✅ Safe File Uploaded"

    else:
        return "ℹ️ Unknown File Type"