"use strict";

// error handler for mobile devices
function hcroak(msg) {
    document.body.innerHTML = msg;
    window.onerror = undefined;
    throw 'fatal_err';
}
function croak(msg) {
    document.body.textContent = msg;
    window.onerror = undefined;
    throw msg;
}
function esc(txt) {
    return txt.replace(/[&"<>]/g, function (c) {
        return {
            '&': '&amp;',
            '"': '&quot;',
            '<': '&lt;',
            '>': '&gt;'
        }[c];
    });
}
window.onerror = function (msg, url, lineNo, columnNo, error) {
    window.onerror = undefined;
    var html = ['<h1>you hit a bug!</h1><p>please screenshot this error and send me a copy arigathanks gozaimuch (ed/irc.rizon.net or ed#2644)</p><p>',
        esc(String(msg)), '</p><p>', esc(url + ' @' + lineNo + ':' + columnNo), '</p>'];

    if (error) {
        var find = ['desc', 'stack', 'trace'];
        for (var a = 0; a < find.length; a++)
            if (String(error[find[a]]) !== 'undefined')
                html.push('<h2>' + find[a] + '</h2>' +
                    esc(String(error[find[a]])).replace(/\n/g, '<br />\n'));
    }
    document.body.style.fontSize = '0.8em';
    hcroak(html.join('\n'));
};


// https://stackoverflow.com/a/950146
function import_js(url, cb) {
    var head = document.head || document.getElementsByTagName('head')[0];
    var script = document.createElement('script');
    script.type = 'text/javascript';
    script.src = url;

    script.onreadystatechange = cb;
    script.onload = cb;

    head.appendChild(script);
}


function o(id) {
    return document.getElementById(id);
}


(function () {
    // chrome requires https to use crypto.subtle,
    // usually it's undefined but some chromes throw on invoke
    try {
        crypto.subtle.digest(
            'SHA-512', new Uint8Array(1)
        ).then(
            function (x) { up2k_init(true) },
            function (x) { up2k_init(false) }
        );
    }
    catch (ex) {
        up2k_init(false);
    }
})();


function up2k_init(have_crypto) {
    //have_crypto = false;
    var need_filereader_cache = undefined;

    // show modal message
    function showmodal(msg) {
        o('u2notbtn').innerHTML = msg;
        o('u2btn').style.display = 'none';
        o('u2notbtn').style.display = 'block';
        o('u2conf').style.opacity = '0.5';
    }

    // hide modal message
    function unmodal() {
        o('u2notbtn').style.display = 'none';
        o('u2btn').style.display = 'block';
        o('u2conf').style.opacity = '1';
        o('u2notbtn').innerHTML = '';
    }

    var post_url = o('bup').getElementsByTagName('form')[0].getAttribute('action');
    if (post_url && post_url.charAt(post_url.length - 1) !== '/')
        post_url += '/';

    var shame = 'your browser <a href="https://www.chromium.org/blink/webcrypto">disables sha512</a> unless you <a href="' + (window.location + '').replace(':', 's:') + '">use https</a>'
    var is_https = (window.location + '').indexOf('https:') === 0;
    if (is_https)
        // chrome<37 firefox<34 edge<12 ie<11 opera<24 safari<10.1
        shame = 'your browser is impressively ancient';

    // upload ui hidden by default, clicking the header shows it
    function toggle_upload_visible(ev) {
        if (ev)
            ev.preventDefault();
        
        o('u2tgl').style.display = 'none';
        o('u2body').style.display = 'block';

        if (!have_crypto && !window.asmCrypto) {
            showmodal('<h1>loading sha512.js</h1><h2>since ' + shame + '</h2><h4>thanks chrome</h4>');
            import_js('/.cpr/deps/sha512.js', unmodal);

            if (is_https)
                o('u2foot').innerHTML = shame + ' so <em>this</em> uploader will do like 500kB/s at best';
            else
                o('u2foot').innerHTML = 'seems like ' + shame + ' so do that if you want more performance';
        }
    };
    o('u2tgl').onclick = toggle_upload_visible;
    
    // show uploader if the user only has write-access
    if (!o('files'))
        toggle_upload_visible();

    // shows or clears an error message in the basic uploader ui
    function setmsg(msg) {
        if (msg !== undefined) {
            o('u2err').setAttribute('class', 'err');
            o('u2err').innerHTML = msg;
        }
        else {
            o('u2err').setAttribute('class', '');
            o('u2err').innerHTML = '';
        }
    }

    // switches to the basic uploader with msg as error message
    function un2k(msg) {
        o('up2k').style.display = 'none';
        o('bup').style.display = 'block';
        setmsg(msg);
    }

    // handle user intent to use the basic uploader instead
    o('u2nope').onclick = function (e) {
        e.preventDefault();
        un2k();
    };

    if (!String.prototype.format) {
        String.prototype.format = function () {
            var args = arguments;
            return this.replace(/{(\d+)}/g, function (match, number) {
                return typeof args[number] != 'undefined' ?
                    args[number] : match;
            });
        };
    }

    function cfg_get(name) {
        var val = localStorage.getItem(name);
        if (val === null)
            return parseInt(o(name).value);

        o(name).value = val
        return val;
    }

    function bcfg_get(name, defval) {
        var val = localStorage.getItem(name);
        if (val === null)
            val = defval;
        else
            val = (val == '1');

        o(name).checked = val;
        return val;
    }

    function bcfg_set(name, val) {
        localStorage.setItem(
            name, val ? '1' : '0');

        o(name).checked = val;
        return val;
    }

    var parallel_uploads = cfg_get('nthread');
    var multitask = bcfg_get('multitask', true);

    var col_hashing = '#00bbff';
    var col_hashed = '#004466';
    var col_uploading = '#ffcc44';
    var col_uploaded = '#00bb00';
    var fdom_ctr = 0;
    var st = {
        "files": [],
        "todo": {
            "hash": [],
            "handshake": [],
            "upload": []
        },
        "busy": {
            "hash": [],
            "handshake": [],
            "upload": []
        }
    };

    var bobslice = File.prototype.slice || File.prototype.mozSlice || File.prototype.webkitSlice;

    if (!bobslice || !window.FileReader || !window.FileList)
        return un2k("this is the basic uploader; up2k needs at least<br />chrome 21 // firefox 13 // edge 12 // opera 12 // safari 5.1");

    // probably safe now
    o('up2k').style.display = 'block';
    o('bup').style.display = 'none';

    function nav() {
        o('file' + fdom_ctr).click();
    }
    o('u2btn').addEventListener('click', nav, false);

    function ondrag(ev) {
        ev.stopPropagation();
        ev.preventDefault();
        ev.dataTransfer.dropEffect = 'copy';
        ev.dataTransfer.effectAllowed = 'copy';
    }
    o('u2btn').addEventListener('dragover', ondrag, false);
    o('u2btn').addEventListener('dragenter', ondrag, false);

    function gotfile(ev) {
        ev.stopPropagation();
        ev.preventDefault();

        var files;
        var is_itemlist = false;
        if (ev.dataTransfer) {
            if (ev.dataTransfer.items) {
                files = ev.dataTransfer.items; // DataTransferItemList
                is_itemlist = true;
            }
            else files = ev.dataTransfer.files; // FileList
        }
        else files = ev.target.files;

        if (files.length == 0)
            return alert('no files selected??');

        more_one_file();
        var bad_files = [];
        for (var a = 0; a < files.length; a++) {
            var fobj = files[a];
            if (is_itemlist) {
                if (fobj.kind !== 'file')
                    continue;

                fobj = fobj.getAsFile();
            }
            try {
                if (fobj.size < 1)
                    throw 1;
            }
            catch (ex) {
                bad_files.push([a, fobj.name]);
                continue;
            }
            var entry = {
                "n": parseInt(st.files.length.toString()),
                "t0": new Date().getTime(),  // TODO remove probably
                "fobj": fobj,
                "name": fobj.name,
                "size": fobj.size,
                "hash": []
            };

            var skip = false;
            for (var b = 0; b < st.files.length; b++)
                if (entry.name == st.files[b].name &&
                    entry.size == st.files[b].size)
                    skip = true;

            if (skip)
                continue;

            var tr = document.createElement('tr');
            tr.innerHTML = '<td></td><td id="f{0}t">hashing</td><td id="f{0}p" class="prog"></td>'.format(st.files.length);
            tr.getElementsByTagName('td')[0].textContent = entry.name;
            o('u2tab').appendChild(tr);

            st.files.push(entry);
            st.todo.hash.push(entry);
        }

        if (bad_files.length > 0) {
            var msg = 'These {0} files (of {1} total) were skipped because they are empty:\n'.format(bad_files.length, files.length);
            for (var a = 0; a < bad_files.length; a++)
                msg += '-- ' + bad_files[a][1] + '\n';

            if (files.length - bad_files.length <= 1 && /(android)/i.test(navigator.userAgent))
                msg += '\nFirefox-Android has a bug which prevents selecting multiple files. Try selecting one file at a time. For more info, see firefox bug 1456557';

            alert(msg);
        }
    }
    o('u2btn').addEventListener('drop', gotfile, false);

    function more_one_file() {
        fdom_ctr++;
        var elm = document.createElement('div')
        elm.innerHTML = '<input id="file{0}" type="file" name="file{0}[]" multiple="multiple" />'.format(fdom_ctr);
        o('u2form').appendChild(elm);
        o('file' + fdom_ctr).addEventListener('change', gotfile, false);
    }
    more_one_file();

    /////
    ////
    ///   actuator
    //

    function handshakes_permitted() {
        return multitask || (
            st.todo.upload.length == 0 &&
            st.busy.upload.length == 0);
    }

    function hashing_permitted() {
        return multitask || (
            handshakes_permitted() &&
            st.todo.handshake.length == 0 &&
            st.busy.handshake.length == 0);
    }

    var tasker = (function () {
        var mutex = false;

        function taskerd() {
            if (mutex)
                return;

            mutex = true;
            while (true) {
                var mou_ikkai = false;

                if (handshakes_permitted() &&
                    st.todo.handshake.length > 0 &&
                    st.busy.handshake.length == 0 &&
                    st.busy.upload.length < parallel_uploads) {
                    exec_handshake();
                    mou_ikkai = true;
                }

                if (st.todo.upload.length > 0 &&
                    st.busy.upload.length < parallel_uploads) {
                    exec_upload();
                    mou_ikkai = true;
                }

                if (hashing_permitted() &&
                    st.todo.hash.length > 0 &&
                    st.busy.hash.length == 0) {
                    exec_hash();
                    mou_ikkai = true;
                }

                if (!mou_ikkai) {
                    setTimeout(taskerd, 100);
                    mutex = false;
                    return;
                }
            }
        }
        taskerd();
        return taskerd;
    })();

    /////
    ////
    ///   hashing
    //

    // https://gist.github.com/jonleighton/958841
    function buf2b64_maybe_fucky(buffer) {
        var ret = '';
        var view = new DataView(buffer);
        for (var i = 0; i < view.byteLength; i++) {
            ret += String.fromCharCode(view.getUint8(i));
        }
        return window.btoa(ret).replace(
            /\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    // https://gist.github.com/jonleighton/958841
    function buf2b64(arrayBuffer) {
        var base64 = '';
        var encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        var bytes = new Uint8Array(arrayBuffer);
        var byteLength = bytes.byteLength;
        var byteRemainder = byteLength % 3;
        var mainLength = byteLength - byteRemainder;
        var a, b, c, d;
        var chunk;

        for (var i = 0; i < mainLength; i = i + 3) {
            chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
            // create 8*3=24bit segment then split into 6bit segments
            a = (chunk & 16515072) >> 18; // 16515072 = (2^6 - 1) << 18
            b = (chunk & 258048) >> 12; // 258048   = (2^6 - 1) << 12
            c = (chunk & 4032) >> 6; // 4032     = (2^6 - 1) << 6
            d = chunk & 63;               // 63       = 2^6 - 1

            // Convert the raw binary segments to the appropriate ASCII encoding
            base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d];
        }

        if (byteRemainder == 1) {
            chunk = bytes[mainLength];
            a = (chunk & 252) >> 2; // 252 = (2^6 - 1) << 2
            b = (chunk & 3) << 4; // 3   = 2^2 - 1  (zero 4 LSB)
            base64 += encodings[a] + encodings[b];//+ '==';
        }
        else if (byteRemainder == 2) {
            chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1];
            a = (chunk & 64512) >> 10; // 64512 = (2^6 - 1) << 10
            b = (chunk & 1008) >> 4; // 1008  = (2^6 - 1) << 4
            c = (chunk & 15) << 2; // 15    = 2^4 - 1  (zero 2 LSB)
            base64 += encodings[a] + encodings[b] + encodings[c];//+ '=';
        }

        return base64;
    }

    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
    function buf2hex(buffer) {
        var hexCodes = [];
        var view = new DataView(buffer);
        for (var i = 0; i < view.byteLength; i += 4) {
            var value = view.getUint32(i) // 4 bytes per iter
            var stringValue = value.toString(16) // doesn't pad
            var padding = '00000000'
            var paddedValue = (padding + stringValue).slice(-padding.length)
            hexCodes.push(paddedValue);
        }
        return hexCodes.join("");
    }

    function get_chunksize(filesize) {
        var chunksize = 1024 * 1024;
        var stepsize = 512 * 1024;
        while (true) {
            for (var mul = 1; mul <= 2; mul++) {
                var nchunks = Math.ceil(filesize / chunksize);
                if (nchunks <= 256 || chunksize >= 32 * 1024 * 1024)
                    return chunksize;

                chunksize += stepsize;
                stepsize *= mul;
            }
        }
    }

    function test_filereader_speed(segm_err) {
        var f = st.todo.hash[0].fobj,
            sz = Math.min(2, f.size),
            reader = new FileReader(),
            t0, ctr = 0;

        var segm_next = function () {
            var t = new Date().getTime(),
                td = t - t0;

            if (++ctr > 2) {
                need_filereader_cache = td > 50;
                st.busy.hash.pop();
                return;
            }
            t0 = t;
            reader.onload = segm_next;
            reader.onerror = segm_err;
            reader.readAsArrayBuffer(
                bobslice.call(f, 0, sz));
        };

        segm_next();
    }

    function ensure_rendered(func) {
        var hidden = false;
        var keys = ['hidden', 'msHidden', 'webkitHidden'];
        for (var a = 0; a < keys.length; a++)
            if (typeof document[keys[a]] !== "undefined")
                hidden = document[keys[a]];

        if (hidden)
            return func();

        window.requestAnimationFrame(func);
    }

    function exec_hash() {
        if (need_filereader_cache === undefined) {
            st.busy.hash.push(1);
            return test_filereader_speed(segm_err);
        }

        var t = st.todo.hash.shift();
        st.busy.hash.push(t);
        t.t1 = new Date().getTime();

        var nchunk = 0;
        var chunksize = get_chunksize(t.size);
        var nchunks = Math.ceil(t.size / chunksize);

        // android-chrome has 180ms latency on FileReader calls,
        // detect this and do 32MB at a time
        var cache_buf = undefined,
            cache_ofs = 0,
            subchunks = 2;

        while (subchunks * chunksize <= 32 * 1024 * 1024)
            subchunks++;

        subchunks--;
        if (!need_filereader_cache)
            subchunks = 1;

        var pb_html = '';
        var pb_perc = 99.9 / nchunks;
        for (var a = 0; a < nchunks; a++)
            pb_html += '<div id="f{0}p{1}" style="width:{2}%"><div></div></div>'.format(
                t.n, a, pb_perc);

        o('f{0}p'.format(t.n)).innerHTML = pb_html;

        var reader = new FileReader();

        var segm_next = function () {
            if (cache_buf) {
                return hash_calc();
            }
            reader.onload = segm_load;
            reader.onerror = segm_err;

            var car = nchunk * chunksize;
            var cdr = car + chunksize * subchunks;
            if (cdr >= t.size)
                cdr = t.size;

            reader.readAsArrayBuffer(
                bobslice.call(t.fobj, car, cdr));

            prog(t.n, nchunk, col_hashing);
        };

        var segm_load = function (ev) {
            cache_buf = ev.target.result;
            cache_ofs = 0;
            hash_calc();
        };

        var hash_calc = function () {
            var buf = cache_buf;
            if (chunksize >= buf.byteLength)
                cache_buf = undefined;
            else {
                var ofs = cache_ofs;
                var ofs2 = ofs + Math.min(chunksize, cache_buf.byteLength - cache_ofs);
                cache_ofs = ofs2;
                buf = new Uint8Array(cache_buf).subarray(ofs, ofs2);
                if (ofs2 >= cache_buf.byteLength)
                    cache_buf = undefined;
            }

            var func = function () {
                if (have_crypto)
                    crypto.subtle.digest('SHA-512', buf).then(hash_done);
                else {
                    var hasher = new asmCrypto.Sha512();
                    hasher.process(new Uint8Array(buf));
                    hasher.finish();
                    hash_done(hasher.result);
                }
            };

            if (cache_buf)
                ensure_rendered(func);
            else
                func();
        };

        var hash_done = function (hashbuf) {
            var hslice = new Uint8Array(hashbuf).subarray(0, 32);
            var b64str = buf2b64(hslice).replace(/=$/, '');
            t.hash.push(b64str);

            prog(t.n, nchunk, col_hashed);
            if (++nchunk < nchunks) {
                prog(t.n, nchunk, col_hashing);
                return segm_next();
            }

            t.t2 = new Date().getTime();
            if (t.n == 0 && window.location.hash == '#dbg') {
                var spd = (t.size / ((t.t2 - t.t1) / 1000.)) / (1024 * 1024.);
                alert('{0} ms, {1} MB/s\n'.format(t.t2 - t.t1, spd.toFixed(3)) + t.hash.join('\n'));
            }

            o('f{0}t'.format(t.n)).innerHTML = 'connecting';
            st.busy.hash.splice(st.busy.hash.indexOf(t), 1);
            st.todo.handshake.push(t);
        };

        var segm_err = function () {
            alert('y o u   b r o k e    i t\n\n(was that a folder? just files please)');
        };

        segm_next();
    }

    /////
    ////
    ///   handshake
    //

    function exec_handshake() {
        var t = st.todo.handshake.shift();
        st.busy.handshake.push(t);

        var xhr = new XMLHttpRequest();
        xhr.onload = function (ev) {
            if (xhr.status == 200) {
                var response = JSON.parse(xhr.responseText);

                t.postlist = [];
                t.wark = response.wark;
                var missing = response.hash;
                for (var a = 0; a < missing.length; a++) {
                    var idx = t.hash.indexOf(missing[a]);
                    if (idx < 0)
                        return alert('wtf negative index for hash "{0}" in task:\n{1}'.format(
                            missing[a], JSON.stringify(t)));

                    t.postlist.push(idx);
                }
                for (var a = 0; a < t.hash.length; a++)
                    prog(t.n, a, (t.postlist.indexOf(a) == -1)
                        ? col_uploaded : col_hashed);

                var done = true;
                var msg = '&#x1f3b7;&#x1f41b;';
                if (t.postlist.length > 0) {
                    for (var a = 0; a < t.postlist.length; a++)
                        st.todo.upload.push({
                            'nfile': t.n,
                            'npart': t.postlist[a]
                        });

                    msg = 'uploading';
                    done = false;
                }
                o('f{0}t'.format(t.n)).innerHTML = msg;
                st.busy.handshake.splice(st.busy.handshake.indexOf(t), 1);

                if (done) {
                    var spd1 = (t.size / ((t.t2 - t.t1) / 1000.)) / (1024 * 1024.);
                    var spd2 = (t.size / ((t.t3 - t.t2) / 1000.)) / (1024 * 1024.);
                    o('f{0}p'.format(t.n)).innerHTML = 'hash {0}, up {1} MB/s'.format(
                        spd1.toFixed(2), spd2.toFixed(2));
                }
                tasker();
            }
            else
                alert("server broke (error {0}):\n\"{1}\"\n".format(
                    xhr.status,
                    (xhr.response && xhr.response.err) ||
                    (xhr.responseText && xhr.responseText) ||
                    "no further information"));
        };
        xhr.open('POST', post_url + 'handshake.php', true);
        xhr.responseType = 'text';
        xhr.send(JSON.stringify({
            "name": t.name,
            "size": t.size,
            "hash": t.hash
        }));
    }

    /////
    ////
    ///   upload
    //

    function exec_upload() {
        var upt = st.todo.upload.shift();
        st.busy.upload.push(upt);

        var npart = upt.npart;
        var t = st.files[upt.nfile];

        prog(t.n, npart, col_uploading);

        var chunksize = get_chunksize(t.size);
        var car = npart * chunksize;
        var cdr = car + chunksize;
        if (cdr >= t.size)
            cdr = t.size;

        var reader = new FileReader();

        reader.onerror = function () {
            alert('y o u   b r o k e    i t\n\n(was that a folder? just files please)');
        };

        reader.onload = function (ev) {
            var xhr = new XMLHttpRequest();
            xhr.upload.onprogress = function (xev) {
                var perc = xev.loaded / (cdr - car) * 100;
                prog(t.n, npart, '', perc);
            };
            xhr.onload = function (xev) {
                if (xhr.status == 200) {
                    prog(t.n, npart, col_uploaded);
                    st.busy.upload.splice(st.busy.upload.indexOf(upt), 1);
                    t.postlist.splice(t.postlist.indexOf(npart), 1);
                    if (t.postlist.length == 0) {
                        t.t3 = new Date().getTime();
                        o('f{0}t'.format(t.n)).innerHTML = 'verifying';
                        st.todo.handshake.push(t);
                    }
                    tasker();
                }
                else
                    alert("server broke (error {0}):\n\"{1}\"\n".format(
                        xhr.status,
                        (xhr.response && xhr.response.err) ||
                        (xhr.responseText && xhr.responseText) ||
                        "no further information"));
            };
            xhr.open('POST', post_url + 'chunkpit.php', true);
            //xhr.setRequestHeader("X-Up2k-Hash", t.hash[npart].substr(1) + "x");
            xhr.setRequestHeader("X-Up2k-Hash", t.hash[npart]);
            xhr.setRequestHeader("X-Up2k-Wark", t.wark);
            xhr.setRequestHeader('Content-Type', 'application/octet-stream');
            xhr.overrideMimeType('Content-Type', 'application/octet-stream');
            xhr.responseType = 'text';
            xhr.send(ev.target.result);
        };

        reader.readAsArrayBuffer(bobslice.call(t.fobj, car, cdr));
    }

    /////
    ////
    ///   progress bar
    //

    function prog(nfile, nchunk, color, percent) {
        var n1 = o('f{0}p{1}'.format(nfile, nchunk));
        var n2 = n1.getElementsByTagName('div')[0];
        if (percent === undefined) {
            n1.style.background = color;
            n2.style.display = 'none';
        }
        else {
            n2.style.width = percent + '%';
            n2.style.display = 'block';
        }
    }

    /////
    ////
    ///   config ui
    //

    function bumpthread(dir) {
        try {
            dir.stopPropagation();
            dir.preventDefault();
        } catch (ex) { }

        var obj = o('nthread');
        if (dir.target) {
            obj.style.background = '#922';
            var v = Math.floor(parseInt(obj.value));
            if (v < 1 || v > 8 || v !== v)
                return;

            parallel_uploads = v;
            localStorage.setItem('nthread', v);
            obj.style.background = '#444';
            return;
        }

        parallel_uploads += dir;

        if (parallel_uploads < 1)
            parallel_uploads = 1;

        if (parallel_uploads > 8)
            parallel_uploads = 8;

        obj.value = parallel_uploads;
        bumpthread({ "target": 1 })
    }

    function tgl_multitask() {
        multitask = !multitask;
        bcfg_set('multitask', multitask);
    }

    function nop(ev) {
        ev.preventDefault();
        this.click();
    }

    o('nthread_add').onclick = function (ev) {
        ev.preventDefault();
        bumpthread(1);
    };
    o('nthread_sub').onclick = function (ev) {
        ev.preventDefault();
        bumpthread(-1);
    };

    o('nthread').addEventListener('input', bumpthread, false);
    o('multitask').addEventListener('click', tgl_multitask, false);

    var nodes = o('u2conf').getElementsByTagName('a');
    for (var a = nodes.length - 1; a >= 0; a--)
        nodes[a].addEventListener('touchend', nop, false);

    bumpthread({ "target": 1 })
}
