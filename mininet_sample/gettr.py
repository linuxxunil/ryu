class Demo:
    def __init__(self):
            self.x = "demo_x"
            self.y = "demo_y"

    def test(self):
            print "demo_test"

demo = Demo()
print getattr(demo, "__init__")
print getattr(demo, "x")
print getattr(demo, "y")
