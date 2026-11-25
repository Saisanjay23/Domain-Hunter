from typing import Dict, Any, Optional
import imagehash


def calculate_similarity(phash1_str: Optional[str], phash2_str: Optional[str]) -> Dict[str, Any]:
    """
    Computes Hamming Distance and percentage similarity between two 64-bit hex pHash strings.
    Returns:
      {
        "distance": int,
        "similarity_percent": float,
        "confidence": str,
        "match_verdict": str
      }
    """
    if not phash1_str or not phash2_str:
        return {
            "distance": None,
            "similarity_percent": 0.0,
            "confidence": "UNKNOWN",
            "match_verdict": "Unable to calculate pHash (unsupported format or missing visual data)",
        }

    try:
        h1 = imagehash.hex_to_hash(phash1_str)
        h2 = imagehash.hex_to_hash(phash2_str)
        distance = int(h1 - h2)  # Cast numpy.int64 to native int

        sim_percent = float(max(0.0, round((1.0 - (distance / 64.0)) * 100, 1)))

        if distance == 0:
            confidence = "EXACT_VISUAL_MATCH"
            verdict = "Identical visual image (100% match, different encoding or identical)"
        elif distance <= 6:
            confidence = "HIGH_CONFIDENCE_VARIANT"
            verdict = f"High Confidence Phishing/Impersonation Variant ({sim_percent}% match, distance: {distance} bits)"
        elif distance <= 12:
            confidence = "MODERATE_SIMILARITY"
            verdict = f"Moderate Visual Similarity ({sim_percent}% match, distance: {distance} bits - potential cropped or modified logo)"
        else:
            confidence = "DISTINCT"
            verdict = f"Distinct images ({sim_percent}% match, distance: {distance} bits - unlikely match)"

        return {
            "distance": distance,
            "similarity_percent": sim_percent,
            "confidence": confidence,
            "match_verdict": verdict,
        }
    except Exception as e:
        return {
            "distance": None,
            "similarity_percent": 0.0,
            "confidence": "ERROR",
            "match_verdict": f"Error computing similarity: {str(e)}",
        }
