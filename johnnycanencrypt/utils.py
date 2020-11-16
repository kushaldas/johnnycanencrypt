createdb = """
CREATE TABLE keys (
	id INTEGER PRIMARY KEY,
	keyvalue BLOB NOT NULL,
	fingerprint TEXT NOT NULL,
	expiration TEXT,
	creation TEXT,
	keytype INTEGER
);

CREATE TABLE subkeys (
	id INTEGER PRIMARY KEY,
	key_id INTEGER,
	fingerprint TEXT NOT NULL,
	keyid TEXT NOT NULL,
	FOREIGN KEY (key_id)
	REFERENCES keys (id)
		ON DELETE CASCADE
);

CREATE TABLE uidvalues (
	id INTEGER PRIMARY KEY,
	value TEXT,
	key_id INTEGER,
	FOREIGN KEY (key_id)
	REFERENCES keys (id)
		ON DELETE CASCADE
);

CREATE TABLE uidemails (
	id INTEGER PRIMARY KEY,
	value TEXT,
	key_id INTEGER,
	value_id INTEGER,
	FOREIGN KEY (key_id)
	REFERENCES keys (id)
		ON DELETE CASCADE
	FOREIGN KEY (value_id)
	REFERENCES uidvalues (id)
		ON DELETE CASCADE
);

CREATE TABLE uidnames (
	id INTEGER PRIMARY KEY,
	value TEXT,
	key_id INTEGER,
	value_id INTEGER,
	FOREIGN KEY (key_id)
	REFERENCES keys (id)
		ON DELETE CASCADE
	FOREIGN KEY (value_id)
	REFERENCES uidvalues (id)
		ON DELETE CASCADE
);

CREATE TABLE uiduris (
	id INTEGER PRIMARY KEY,
	value TEXT,
	key_id INTEGER,
	value_id INTEGER,
	FOREIGN KEY (key_id)
	REFERENCES keys (id)
		ON DELETE CASCADE
	FOREIGN KEY (value_id)
	REFERENCES uidvalues (id)
		ON DELETE CASCADE
);
"""


def _get_cert_data(filepath):
    "Returns the filepath content as bytes"
    with open(filepath, "rb") as fobj:
        return fobj.read()
