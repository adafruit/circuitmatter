import json


class PersistentDictionary:
    """This acts like a dictionary and is persisted when values change."""

    def __init__(self, filename=None, root=None, state=None):
        self.filename = filename
        self.root = root
        self.dirty = False
        self.persisted = {}
        self._state: dict
        if self.root is None and filename:
            with open(self.filename, "r") as state_file:
                self._state = json.load(state_file)
        elif state is not None:
            self._state = state
        else:
            raise ValueError("Provide filename or (root and state)")

    def wrap(self, value):
        return value

    def __setitem__(self, key, value):
        self._state[key] = value
        if self.root:
            self.root.dirty = True
        else:
            self.dirty = True

    def __getitem__(self, key):
        value = self._state[key]
        if isinstance(value, dict):
            if key not in self.persisted:
                root = self.root if self.root else self
                self.persisted[key] = PersistentDictionary(root=root, state=value)
            return self.persisted[key]
        return value

    def __delitem__(self, key):
        del self._state[key]
        if self.root:
            self.root.dirty = True
        else:
            self.dirty = True

    def keys(self):
        return self._state.keys()

    def __iter__(self):
        return iter(self._state)

    def commit(self):
        if not self.dirty:
            return
        if self.root:
            self.root.commit()
            return
        with open(self.filename, "w") as state_file:
            json.dump(self._state, state_file, indent=1)
        self.dirty = False
