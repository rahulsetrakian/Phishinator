# Phishinator - Rule-Based Phishing Email Analyser

Phishinator is Rule-Based Phishing Email Analyser which works in the web, and uses LLM to categorize the findings into various types.

#### Video Demo:  <URL HERE>

### Description:


### Installation

```
    ./tailwindcss -i app/static/css/input.css -o app/static/css/output.css --watch
```


### Directory Structure

```
    phishinator/
    ├── app/
    │   ├── __init__.py
    │   ├── config.py
    │   │
    │   ├── routes/
    │   │   ├── main.py
    │   │   ├── analyser.py
    │   │   └── learn.py
    │   │
    │   ├── services/
    │   │   ├── parser.py
    │   │   ├── rules.py
    │   │   ├── scorer.py
    │   │   └── llm.py
    │   │
    │   ├── templates/
    │   │   ├── base.html
    │   │   ├── index.html
    │   │   ├── upload.html
    │   │   ├── result.html
    │   │   └── glossary.html
    │   │
    │   └── static/
    │       ├── css/
    │       └── js/
    │
    ├── instance/
    │   └── uploads/
    │
    ├── tests/
    │   ├── test_parser.py
    │   └── test_rules.py
    │
    ├── app.py
    ├── requirements.txt
    ├── .env
    └── README.md
```


### library:

1. https://docs.python.org/3/library/email.html
