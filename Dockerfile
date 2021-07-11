FROM python:3.8-slim-buster

WORKDIR /

COPY const.py const.py
COPY slave_src.py slave_src.py
COPY slave.py slave.py

CMD [ "python3", "-u", "slave.py"]