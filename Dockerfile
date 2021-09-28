FROM python:3.9

RUN mkdir /code
WORKDIR /code
ADD pyproject.toml /code/
ADD poetry.lock /code/
ADD README.md /code/

RUN pip install poetry==1.2.0a2 \
    && poetry config virtualenvs.create false \
    && poetry install --without dev --no-interaction --no-root

ADD docker_simple_dns /code/docker_simple_dns
RUN poetry install --without dev --no-interaction

ENV PYTHONUNBUFFERED=1

CMD ["docker_simple_dns"]



