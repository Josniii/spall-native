rm -rf bin/spall.app
mkdir bin/spall.app
mkdir bin/spall.app/Contents
mkdir bin/spall.app/Contents/MacOS
mkdir bin/spall.app/Contents/resources
cp bin/spall bin/spall.app/Contents/MacOS/.
cp resources/info.plist bin/spall.app/Contents/.
cp resources/icon.icns bin/spall.app/Contents/resources/
