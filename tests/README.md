# PulseGuard Test Suite

## DISCLAIMER

Ces tests sont generes automatiquement par Claude 4.5 Sonet. A chaque commit, un agent est automatiquement appele pour s'assurer que le coverage est > 70% et genere les tests en consequence.

Simple test suite for the password manager.

## Running locally

```bash
uv pip install -e .[dev,test]
uv run pytest --cov=pulseguard --cov-report=html
```
