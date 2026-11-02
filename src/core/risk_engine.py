def assess_risk_tier(tag_name: str) -> str:
    """Profiles metadata tag names against privacy risk dictionaries."""
    tag_lower = str(tag_name).lower()

    # Intrinsic system properties
    system_triggers = ['hash', 'size', 'name', 'os creation', 'os modification']
    if any(trigger in tag_lower for trigger in system_triggers):
        return "SYSTEM DATA"

    # Privacy risk vectors
    high_risk_triggers = ['gps', 'latitude', 'longitude', 'serial', 'owner', 'author', 'creator']
    med_risk_triggers = ['date', 'time', 'software', 'hardware', 'make', 'model']
    
    if any(trigger in tag_lower for trigger in high_risk_triggers):
        return "HIGH RISK"
    elif any(trigger in tag_lower for trigger in med_risk_triggers):
        return "MEDIUM RISK"
    else:
        return "LOW RISK"