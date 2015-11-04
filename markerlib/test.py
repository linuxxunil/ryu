import os

from nose.tools import assert_true, assert_false, assert_equal, raises
       
def test_markers():
    from markerlib import interpret, default_environment, compile
    
    os_name = os.name
    
    assert_true(interpret(""))
    
    assert_true(interpret("os.name != 'buuuu'"))
    assert_true(interpret("python_version > '1.0'"))
    assert_true(interpret("python_version < '5.0'"))
    assert_true(interpret("python_version <= '5.0'"))
    assert_true(interpret("python_version >= '1.0'"))
    assert_true(interpret("'%s' in os.name" % os_name))
    assert_true(interpret("'%s' in os_name" % os_name))
    assert_true(interpret("'buuuu' not in os.name"))
    
    assert_false(interpret("os.name == 'buuuu'"))
    assert_false(interpret("os_name == 'buuuu'"))
    assert_false(interpret("python_version < '1.0'"))
    assert_false(interpret("python_version > '5.0'"))
    assert_false(interpret("python_version >= '5.0'"))
    assert_false(interpret("python_version <= '1.0'"))
    assert_false(interpret("'%s' not in os.name" % os_name))
    assert_false(interpret("'%s' not in os_name" % os_name))
    assert_false(interpret("'buuuu' in os.name and python_version >= '5.0'"))    
    assert_false(interpret("'buuuu' in os_name and python_version >= '5.0'"))    
    
    environment = default_environment()
    environment['extra'] = 'test'
    assert_true(interpret("extra == 'test'", environment))
    assert_false(interpret("extra == 'doc'", environment))
    
    @raises(NameError)
    def raises_nameError():
        interpret("python.version == '42'")
    
    raises_nameError()
    
    @raises(SyntaxError)
    def raises_syntaxError():
        interpret("(x for x in (4,))")
        
    raises_syntaxError()
    
    statement = "python_version == '5'"
    assert_equal(compile(statement).__doc__, statement)

