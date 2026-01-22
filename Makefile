kill:
	lsof -t -i :8000 | xargs kill -9;
