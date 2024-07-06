rm -rf bin
mkdir bin

if [ "$1" = "release" ]; then
	odin build src -collection:formats=formats -out:bin/spall -debug -o:speed -no-bounds-check -define:GL_DEBUG=false -strict-style -minimum-os-version:11.0
elif [ "$1" = "opt" ]; then
	odin build src -collection:formats=formats -out:bin/spall -debug -o:speed -strict-style -minimum-os-version:11.0
else
	odin build src -collection:formats=formats -out:bin/spall -debug -keep-temp-files -strict-style -minimum-os-version:11.0
fi
