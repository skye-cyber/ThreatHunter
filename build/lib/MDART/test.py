
def extracted_method():
    def test(f):
        d = 'hello'

        def check(h):
            print(d, h, f)
        check(f)
    return test


ts = extracted_method()
g = "good"
ts.__call__(g)
