FROM python:3.8-slim-buster
WORKDIR /flask
COPY tc.py /flask
COPY jwtoken /flask/jwtoken
COPY requirements.txt /flask
RUN pip3 install -r requirements.txt
ENV FLASK_RUN_HOST=0.0.0.0
EXPOSE 1111
ENTRYPOINT [ "flask", "--app" , "tc", "run"]