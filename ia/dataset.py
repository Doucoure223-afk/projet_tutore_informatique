"""Small synthetic teaching corpus, NOT the 10,000-record reference dataset.

Entire templates are reserved for validation; variations of a template never
cross partitions. Validation therefore remains synthetic and domain-limited.
"""

import hashlib
from urllib.parse import quote

from features import normalize


# (group id, family, label, partition, template)
TEMPLATES = [
    ("bool_or_number", "boolean", 1, "train", "' OR {n}={n} --"),
    ("bool_or_string", "boolean", 1, "train", "{name}' OR 'x'='x' #"),
    ("bool_and_false", "boolean", 1, "train", "' AND {n}=0 --"),
    ("bool_subselect", "boolean", 1, "train", "' AND (SELECT count(*) FROM users)>{n} --"),
    ("bool_validation", "boolean", 1, "validation", "{n} OR {n}={n}"),
    ("bool_validation_like", "boolean", 1, "validation", "' OR 'hello' LIKE 'h%' -- {name}"),
    ("union_users", "union", 1, "train", "' UNION SELECT id,password FROM users WHERE id={n} --"),
    ("union_all", "union", 1, "train", "{n} UNION ALL SELECT NULL,username FROM users #"),
    ("union_schema", "union", 1, "train", "' UNION SELECT table_name FROM information_schema.tables -- {n}"),
    ("union_comment", "union", 1, "train", "{n} un/**/ion sel/**/ect password FROM users"),
    ("union_validation", "union", 1, "validation", "{n}' UNION SELECT 1,2,3 -- {name}"),
    ("union_validation_null", "union", 1, "validation", "- {n} UNION SELECT NULL,NULL,NULL"),
    ("time_sleep", "time", 1, "train", "' OR SLEEP({n}) --"),
    ("time_benchmark", "time", 1, "train", "' AND BENCHMARK({n}000,MD5('a')) #"),
    ("time_waitfor", "time", 1, "train", "'; WAITFOR DELAY '0:0:{n}' --"),
    ("time_validation", "time", 1, "validation", "{n} AND IF(1=1,SLEEP(4),0)"),
    ("error_extract", "error", 1, "train", "' AND EXTRACTVALUE({n},concat(0x7e,version())) --"),
    ("error_xml", "error", 1, "train", "{n} AND UPDATEXML(1,concat(0x7e,database()),1)"),
    ("error_validation", "error", 1, "validation", "' OR EXTRACTVALUE({n},concat(0x3a,user())) # {name}"),
    ("stack_drop", "stacked", 1, "train", "'; DROP TABLE users; -- {n}"),
    ("stack_delete", "stacked", 1, "train", "'; DELETE FROM users WHERE id={n}; --"),
    ("stack_update", "stacked", 1, "train", "'; UPDATE users SET role='admin' WHERE id={n}; --"),
    ("stack_validation", "stacked", 1, "validation", "{n}; INSERT INTO users(name) VALUES('{name}') --"),
    ("comment_login", "comment", 1, "train", "{name}' --"),
    ("comment_hash", "comment", 1, "train", "{name}' # {n}"),
    ("comment_validation", "comment", 1, "validation", "{name}'/* comment {n} */"),
    ("plain_name", "benign", 0, "train", "{name}"),
    ("plain_email", "benign", 0, "train", "{name}{n}@example.test"),
    ("plain_id", "benign", 0, "train", "{n}2345"),
    ("plain_search", "benign", 0, "train", "ordinateur portable {name} {n}"),
    ("plain_apostrophe", "benign", 0, "train", "L'école de {name}"),
    ("plain_punctuation", "benign", 0, "train", "Bonjour {name}; rendez-vous à {n}h !"),
    ("plain_union", "benign", 0, "train", "union des étudiants {name} {n}"),
    ("plain_sleep", "benign", 0, "train", "sleep mieux {name} {n}"),
    ("plain_password", "benign", 0, "train", "{name}!P@ss#{n}2026"),
    ("plain_doublequote", "benign", 0, "train", 'livre "{name}" tome {n}'),
    ("plain_math", "benign", 0, "train", "prix = {n} euros pour {name}"),
    ("plain_url", "benign", 0, "train", "https://example.test/{name}?page={n}"),
    ("plain_sql_text", "benign", 0, "train", "SELECT title FROM books WHERE id={n}"),
    ("plain_select_lesson", "benign", 0, "train", "cours SELECT et UNION pour {name} niveau {n}"),
    ("plain_phone", "benign", 0, "train", "+223 70 00 {n}0 00"),
    ("plain_accent", "benign", 0, "train", "Sécurité réseau à Bamako avec {name}, groupe {n}"),
    ("plain_validation_name", "benign", 0, "validation", "Mme {name} Traoré {n}"),
    ("plain_validation_apostrophe", "benign", 0, "validation", "O'Connor {name} {n}"),
    ("plain_validation_search", "benign", 0, "validation", "formation cybersécurité {n} pour {name}"),
    ("plain_validation_hyphen", "benign", 0, "validation", "{name} - cahier numéro {n}"),
    ("plain_validation_password", "benign", 0, "validation", "Mdp!{n}_#Abc-{name}"),
    ("plain_validation_select", "benign", 0, "validation", "select a book {name} volume {n}"),
    ("plain_validation_word", "benign", 0, "validation", "drop shipping chez {name} depuis {n} ans"),
    ("plain_validation_email", "benign", 0, "validation", "contact.{name}@entreprise{n}.ml"),
]


def build_dataset():
    records, seen = [], set()
    names = ("amina", "moussa", "fatou", "ibrahim", "mariam", "issa", "adam", "sira")
    for group, family, label, partition, template in TEMPLATES:
        for index, name in enumerate(names, 1):
            sql = template.format(name=name, n=index)
            # Consistent transport variations inside each template group.
            if index == 3:
                sql = quote(sql, safe="")
            elif index == 5:
                sql = sql.upper()
            elif index == 7 and label:
                sql = sql.replace(" ", "/**/")
            fingerprint = hashlib.sha256(normalize(sql)[1].encode("utf-8")).hexdigest()
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            records.append({"sql": sql, "label": label, "family": family,
                            "group": group, "partition": partition, "source": "synthetic_demo"})
    return records
