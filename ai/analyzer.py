import os
from pdfminer.high_level import extract_text

# Minimal canonical skills and role mapping
CANONICAL_SKILLS = [
    'python', 'java', 'javascript', 'react', 'node', 'sql', 'aws', 'docker', 'kubernetes',
    'c++', 'c#', 'go', 'ruby', 'php', 'html', 'css', 'tensorflow', 'pytorch', 'nlp', 'linux'
]

ROLE_MAP = {
    'backend': {'python', 'java', 'node', 'sql', 'docker', 'aws'},
    'frontend': {'javascript', 'react', 'html', 'css', 'typescript' },
    'data_scientist': {'python', 'tensorflow', 'pytorch', 'nlp', 'sql'},
    'devops': {'aws', 'docker', 'kubernetes', 'linux'},
}


def extract_text_from_file(path):
    """Extract plain text from supported file types (pdf, txt)."""
    if not os.path.exists(path):
        return ""
    ext = path.split('.')[-1].lower()
    try:
        if ext == 'pdf':
            text = extract_text(path) or ""
            return text
        elif ext == 'txt':
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        else:
            # unsupported for now
            return ""
    except Exception:
        return ""


def normalize_words(text):
    return [w.strip().lower() for w in text.replace('\n', ' ').split() if w.strip()]


def extract_skills(text):
    words = set(normalize_words(text))
    found = set()
    for skill in CANONICAL_SKILLS:
        if skill.lower() in words:
            found.add(skill.lower())
    # also detect multi-word skill mentions (e.g., "machine learning") naive approach
    # (skip for minimal stub)
    return sorted(found)


def predict_roles(skills):
    scores = {}
    skills_set = set(skills)
    for role, role_skills in ROLE_MAP.items():
        inter = skills_set.intersection(role_skills)
        if inter:
            scores[role] = len(inter)
    # sort roles by matched skill count
    return [r for r, _ in sorted(scores.items(), key=lambda kv: kv[1], reverse=True)]


def compute_ats(profile_skills, resume_skills, experience_years, education):
    """Return ATS-like score 0-100 and missing skills list."""
    try:
        experience = float(experience_years or 0)
    except Exception:
        experience = 0.0

    # skills
    profile_set = set([s.strip().lower() for s in (profile_skills or '').split(',') if s.strip()])
    resume_set = set([s.strip().lower() for s in (resume_skills or []) if s.strip()])

    if profile_set:
        matched = resume_set.intersection(profile_set)
        skill_match_ratio = len(matched) / max(len(profile_set), 1)
        missing = sorted(profile_set - matched)
    else:
        # if user hasn't provided skills, measure against canonical skills found
        canonical = set(resume_set)
        skill_match_ratio = min(1.0, len(canonical) / max(len(CANONICAL_SKILLS), 1))
        missing = []

    # experience score normalized (0-1), clamp at 20 years
    experience_score = min(experience / 20.0, 1.0)

    # education simple mapping
    edu_score = 0
    if education:
        ed = education.lower()
        if 'phd' in ed:
            edu_score = 1.0
        elif 'master' in ed:
            edu_score = 0.85
        elif 'bachelor' in ed:
            edu_score = 0.7
        else:
            edu_score = 0.5

    # weighted sum -> ATS 0-100
    ats = int(min(100, (skill_match_ratio * 0.7 + experience_score * 0.2 + edu_score * 0.1) * 100))

    return {
        'ats_score': ats,
        'skill_match_ratio': round(skill_match_ratio, 2),
        'missing_skills': missing,
        'matched_skills': sorted(list(resume_set.intersection(profile_set))) if profile_set else sorted(list(resume_set)),
    }


def analyze_resume_file(path, profile_skills=None, experience_years=None, education=None):
    text = extract_text_from_file(path)
    skills = extract_skills(text)
    roles = predict_roles(skills)
    ats = compute_ats(profile_skills, skills, experience_years, education)
    suggestions = []
    if ats['ats_score'] < 60:
        suggestions.append('Add relevant keywords and metrics in your projects')
    if ats['ats_score'] < 40:
        suggestions.append('Consider listing measurable outcomes and technologies used')

    return {
        'text_length': len(text),
        'extracted_skills': skills,
        'predicted_roles': roles,
        'ats': ats,
        'suggestions': suggestions,
    }
