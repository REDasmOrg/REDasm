DEPENDS_ROOT = $$PWD/depends

# Capstone
INCLUDEPATH += $$DEPENDS_ROOT/capstone/include
LIBS += -L$$DEPENDS_ROOT/capstone.build -lcapstone

# PicoJSON
INCLUDEPATH += $$DEPENDS_ROOT/picojson
