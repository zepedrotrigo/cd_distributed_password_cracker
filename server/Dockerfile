FROM python:3.8-slim-buster

WORKDIR /

COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt

COPY main.py main.py 
COPY const.py const.py 

CMD [ "python3", "main.py"]
