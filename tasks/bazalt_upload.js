var fs = require('fs'),
    jsencrypt = require('../lib/jsencrypt').JSEncrypt,
    rest = require('restler'),
    crypto = require('crypto'),
    hash = crypto.createHash('md5');

module.exports = function (grunt) {
    'use strict';

    grunt.registerMultiTask('bazalt_upload', 'Upload files through HTTP request with RSA signing', function () {
        var done = this.async(),
            options = this.options({
                method: 'POST',
                headers: {},
                url: '',
                version: '0.0.0',
                public_key: 'public.key'
            });

        grunt.verbose.writeflags(options, 'Options');

        if (!grunt.file.exists(options.public_key)) {
            grunt.fail.warn('Public key "' + options.public_key + '" not found.');
            return false;
        }
        var crypt = new jsencrypt({ default_key_size: 1024 });
        crypt.setPublicKey(fs.readFileSync(options.public_key).toString());

        this.files.forEach(function (file) {
            var filepath = file.src[0], field = file.dest || 'file';

            if (!grunt.file.exists(filepath)) {
                grunt.fail.warn('Source file "' + filepath + '" not found.');
                return false;
            }

            var stream = fs.createReadStream(filepath);

            stream.on('data', function (data) {
                hash.update(data, 'utf8');
            });

            stream.on('end', function () {
                fs.stat(filepath, function (err, stats) {
                    if (err) {
                        grunt.fail.warn('Error: ' + err);
                        done(err);
                    } else if (stats.isFile()) {
                        var fileSize = stats.size;
                        grunt.log.writeln('Uploading "' + filepath + '" as "' + field + '"');

                        var reqData = options.data || {};
                        reqData[field] = rest.file(filepath, null, fileSize, null, null);

                        var headers = options.headers,
                            md5= hash.digest('hex'),
                            message = JSON.stringify({
                                v: options.version,
                                md5: md5,
                                size: fileSize,
                                ctime: stats.ctime.toISOString()
                            }), token;

                        try {
                            token = crypt.encrypt(message);
                        } catch (e) {
                            grunt.fail.fatal('Invalid "' + options.public_key + '" file. Must be RSA public key (openssl rsa -pubout -in "private.key" -out "public.key")');
                        }
                        grunt.log.writeln("Token for deploy: " + token);

                        headers['Authorization'] = 'Token ' + token;

                        rest.request(options.url, {
                            method: options.method,
                            headers: headers,
                            multipart: true,
                            data: reqData
                        }).on('complete', function (data, response) {
                            if (response.statusCode >= 200 && response.statusCode < 300) {
                                grunt.log.ok('Upload successful of "' + filepath + '" as "' + field + '" - ' + options.method + ' @ ' + options.url);
                            } else {
                                try {
                                    var err = JSON.parse(data);
                                } catch (e) {
                                    grunt.fail.fatal(data);
                                }
                                grunt.fail.fatal('Failed uploading "' + filepath + '" as "' + field +
                                    '" (status code: ' + response.statusCode + ', message: ' + err.error + ') - ' +
                                    options.method + ' @ ' + options.url);
                            }
                            done(data);
                        });
                    }
                });
            });
        });
    });
};
