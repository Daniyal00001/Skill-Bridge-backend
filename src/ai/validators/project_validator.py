# ============================================================
# PATH: backend/ai/validators/project_validator.py
# PURPOSE: Logic to validate extracted project requirements
# ============================================================

from typing import Any, Dict, List
from shared.agent_types import ProjectRequirements
from shared.constants import REQUIRED_PROJECT_FIELDS

class ProjectValidator:
    def validate(self, project: ProjectRequirements) -> Dict[str, Any]:
        missing_fields = []
        project_dict = project.dict()

        for field in REQUIRED_PROJECT_FIELDS:
            value = project_dict.get(field)
            if value is None or (isinstance(value, list) and len(value) == 0):
                missing_fields.append(field)

        # Basic confidence calculation
        total_fields = len(REQUIRED_PROJECT_FIELDS) + 2 # techPreferences, expertiseNeeded
        filled_fields = total_fields - len(missing_fields)
        
        if project.techPreferences: filled_fields += 1
        else: missing_fields.append("techPreferences")
        
        if project.expertiseNeeded: filled_fields += 1
        else: missing_fields.append("expertiseNeeded")

        confidence = (filled_fields / (total_fields + 2)) * 100

        return {
            "isComplete": len(missing_fields) == 0,
            "missingFields": missing_fields,
            "confidence": round(confidence, 2)
        }
