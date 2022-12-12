FROM python:3.8-slim-buster
WORKDIR /flask
COPY sp.py /flask
RUN pip3 install flask requests flask_login
ENV FLASK_RUN_HOST=0.0.0.0
EXPOSE 5000
ENTRYPOINT [ "flask", "--app" , "sp", "run"]