"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[785],{3905:(e,t,n)=>{n.d(t,{Zo:()=>p,kt:()=>k});var i=n(7294);function r(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function a(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);t&&(i=i.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,i)}return n}function o(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?a(Object(n),!0).forEach((function(t){r(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):a(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function s(e,t){if(null==e)return{};var n,i,r=function(e,t){if(null==e)return{};var n,i,r={},a=Object.keys(e);for(i=0;i<a.length;i++)n=a[i],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(i=0;i<a.length;i++)n=a[i],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(r[n]=e[n])}return r}var c=i.createContext({}),l=function(e){var t=i.useContext(c),n=t;return e&&(n="function"==typeof e?e(t):o(o({},t),e)),n},p=function(e){var t=l(e.components);return i.createElement(c.Provider,{value:t},e.children)},d="mdxType",m={inlineCode:"code",wrapper:function(e){var t=e.children;return i.createElement(i.Fragment,{},t)}},u=i.forwardRef((function(e,t){var n=e.components,r=e.mdxType,a=e.originalType,c=e.parentName,p=s(e,["components","mdxType","originalType","parentName"]),d=l(n),u=r,k=d["".concat(c,".").concat(u)]||d[u]||m[u]||a;return n?i.createElement(k,o(o({ref:t},p),{},{components:n})):i.createElement(k,o({ref:t},p))}));function k(e,t){var n=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var a=n.length,o=new Array(a);o[0]=u;var s={};for(var c in t)hasOwnProperty.call(t,c)&&(s[c]=t[c]);s.originalType=e,s[d]="string"==typeof e?e:r,o[1]=s;for(var l=2;l<a;l++)o[l]=n[l];return i.createElement.apply(null,o)}return i.createElement.apply(null,n)}u.displayName="MDXCreateElement"},9069:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>c,contentTitle:()=>o,default:()=>d,frontMatter:()=>a,metadata:()=>s,toc:()=>l});var i=n(7462),r=(n(7294),n(3905));const a={title:"Quick Start"},o=void 0,s={unversionedId:"quick-start",id:"version-v0.1.0/quick-start",title:"Quick Start",description:"This sample illustrates how to patch containers using vulnerability reports with copa.",source:"@site/versioned_docs/version-v0.1.0/quick-start.md",sourceDirName:".",slug:"/quick-start",permalink:"/copacetic/website/quick-start",draft:!1,tags:[],version:"v0.1.0",frontMatter:{title:"Quick Start"},sidebar:"sidebar",previous:{title:"Installation",permalink:"/copacetic/website/installation"},next:{title:"Design",permalink:"/copacetic/website/design"}},c={},l=[{value:"Prerequisites",id:"prerequisites",level:2},{value:"Sample Steps",id:"sample-steps",level:2}],p={toc:l};function d(e){let{components:t,...n}=e;return(0,r.kt)("wrapper",(0,i.Z)({},p,n,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("p",null,"This sample illustrates how to patch containers using vulnerability reports with ",(0,r.kt)("inlineCode",{parentName:"p"},"copa"),"."),(0,r.kt)("h2",{id:"prerequisites"},"Prerequisites"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"An Ubuntu 22.04 VM configured through the ",(0,r.kt)("a",{parentName:"li",href:"/copacetic/website/installation"},"setup instructions")," or a VSCode ",(0,r.kt)("a",{parentName:"li",href:"/copacetic/website/contributing/#visual-studio-code-development-container"},"devcontainer")," environment. This includes:",(0,r.kt)("ul",{parentName:"li"},(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"copa")," tool ",(0,r.kt)("a",{parentName:"li",href:"/copacetic/website/installation"},"built & pathed"),"."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"https://github.com/moby/buildkit/#quick-start"},"buildkit")," daemon installed & pathed."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"https://docs.docker.com/desktop/linux/install/#generic-installation-steps"},"docker")," daemon running and CLI installed & pathed."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"https://aquasecurity.github.io/trivy/latest/getting-started/installation/"},"trivy CLI")," installed & pathed.")))),(0,r.kt)("h2",{id:"sample-steps"},"Sample Steps"),(0,r.kt)("ol",null,(0,r.kt)("li",{parentName:"ol"},(0,r.kt)("p",{parentName:"li"},"Download the target container to scan and patch:"),(0,r.kt)("pre",{parentName:"li"},(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"docker pull mcr.microsoft.com/oss/nginx/nginx:1.21.6\n"))),(0,r.kt)("li",{parentName:"ol"},(0,r.kt)("p",{parentName:"li"},"Scan the container image for patchable OS vulnerabilities, outputting the results to a JSON file:"),(0,r.kt)("pre",{parentName:"li"},(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"trivy image --vuln-type os --ignore-unfixed -f json -o nginx.1.21.6.json mcr.microsoft.com/oss/nginx/nginx:1.21.6\n")),(0,r.kt)("p",{parentName:"li"},"You can also see the existing patchable vulnerabilities in table form on the shell with:"),(0,r.kt)("pre",{parentName:"li"},(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"trivy image --vuln-type os --ignore-unfixed mcr.microsoft.com/oss/nginx/nginx:1.21.6\n\n"))),(0,r.kt)("li",{parentName:"ol"},(0,r.kt)("p",{parentName:"li"},"Patch the image using the Trivy report. You will need to start ",(0,r.kt)("inlineCode",{parentName:"p"},"buildkitd")," if it is not already running:"),(0,r.kt)("pre",{parentName:"li"},(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"sudo buildkitd &\nsudo copa patch -i mcr.microsoft.com/oss/nginx/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched\n")),(0,r.kt)("p",{parentName:"li"},"Alternatively, you can run ",(0,r.kt)("inlineCode",{parentName:"p"},"buildkitd")," in a container, which allows copa to be run without root access to the local buildkit socket:"),(0,r.kt)("pre",{parentName:"li"},(0,r.kt)("code",{parentName:"pre",className:"language-bash"},'export BUILDKIT_VERSION=v0.11.4\nexport BUILDKIT_PORT=8888\ndocker run \\\n    --detach \\\n    --rm \\\n    --privileged \\\n    -p 127.0.0.1:$BUILDKIT_PORT:$BUILDKIT_PORT/tcp \\\n    --name buildkitd \\\n    --entrypoint buildkitd \\\n    "moby/buildkit:$BUILDKIT_VERSION" \\\n    --addr tcp://0.0.0.0:$BUILDKIT_PORT\ncopa patch \\\n    -i mcr.microsoft.com/oss/nginx/nginx:1.21.6 \\\n    -r nginx.1.21.6.json \\\n    -t 1.21.6-patched \\\n    -a tcp://0.0.0.0:$BUILDKIT_PORT\n')),(0,r.kt)("p",{parentName:"li"},"In either case, ",(0,r.kt)("inlineCode",{parentName:"p"},"copa")," is non-destructive and exports a new image with the specified ",(0,r.kt)("inlineCode",{parentName:"p"},"1.21.6-patched")," label to the local Docker daemon."),(0,r.kt)("blockquote",{parentName:"li"},(0,r.kt)("p",{parentName:"blockquote"},(0,r.kt)("strong",{parentName:"p"},"NOTE:")," if you're running this sample against an image from a private registry instead,\nensure that the credentials are configured in the default Docker config.json before running ",(0,r.kt)("inlineCode",{parentName:"p"},"copa patch"),",\nfor example, via ",(0,r.kt)("inlineCode",{parentName:"p"},"sudo docker login -u <user> -p <password> <registry>"),"."))),(0,r.kt)("li",{parentName:"ol"},(0,r.kt)("p",{parentName:"li"},"Scan the patched image and verify that the vulnerabilities have been patched:"),(0,r.kt)("pre",{parentName:"li"},(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"trivy image --vuln-type os --ignore-unfixed mcr.microsoft.com/oss/nginx/nginx:1.21.6-patched\n")),(0,r.kt)("p",{parentName:"li"},"You can also inspect the structure of the patched image with ",(0,r.kt)("inlineCode",{parentName:"p"},"docker history")," to see the new patch layer appended to the image:"),(0,r.kt)("pre",{parentName:"li"},(0,r.kt)("code",{parentName:"pre",className:"language-bash"},'$ docker history mcr.microsoft.com/oss/nginx/nginx:1.21.6-patched\nIMAGE          CREATED        CREATED BY                                      SIZE      COMMENT\na372df41e06d   1 minute ago   mount / from exec sh -c apt install --no-ins\u2026   26.1MB    buildkit.exporter.image.v0\n<missing>      3 months ago   CMD ["nginx" "-g" "daemon off;"]                0B        buildkit.dockerfile.v0\n<missing>      3 months ago   STOPSIGNAL SIGQUIT                              0B        buildkit.dockerfile.v0\n<missing>      3 months ago   EXPOSE map[80/tcp:{}]                           0B        buildkit.dockerfile.v0\n<missing>      3 months ago   ENTRYPOINT ["/docker-entrypoint.sh"]            0B        buildkit.dockerfile.v0\n<missing>      3 months ago   COPY 30-tune-worker-processes.sh /docker-ent\u2026   4.61kB    buildkit.dockerfile.v0\n<missing>      3 months ago   COPY 20-envsubst-on-templates.sh /docker-ent\u2026   1.04kB    buildkit.dockerfile.v0\n<missing>      3 months ago   COPY 10-listen-on-ipv6-by-default.sh /docker\u2026   1.96kB    buildkit.dockerfile.v0\n<missing>      3 months ago   COPY docker-entrypoint.sh / # buildkit          1.2kB     buildkit.dockerfile.v0\n<missing>      3 months ago   RUN /bin/sh -c set -x     && addgroup --syst\u2026   61.1MB    buildkit.dockerfile.v0\n<missing>      3 months ago   ENV PKG_RELEASE=1~bullseye                      0B        buildkit.dockerfile.v0\n<missing>      3 months ago   ENV NJS_VERSION=0.7.0                           0B        buildkit.dockerfile.v0\n<missing>      3 months ago   ENV NGINX_VERSION=1.20.2                        0B        buildkit.dockerfile.v0\n<missing>      3 months ago   LABEL maintainer=NGINX Docker Maintainers <d\u2026   0B        buildkit.dockerfile.v0\n<missing>      4 months ago   /bin/sh -c #(nop)  CMD ["bash"]                 0B\n<missing>      4 months ago   /bin/sh -c #(nop) ADD file:09675d11695f65c55\u2026   80.4MB\n'))),(0,r.kt)("li",{parentName:"ol"},(0,r.kt)("p",{parentName:"li"},"Run the container to verify that the image has no regressions:"),(0,r.kt)("pre",{parentName:"li"},(0,r.kt)("code",{parentName:"pre",className:"language-bash"},'$ docker run -it --rm --name nginx-test mcr.microsoft.com/oss/nginx/nginx:1.21.6-patched\n/docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configuration\n/docker-entrypoint.sh: Looking for shell scripts in /docker-entrypoint.d/\n/docker-entrypoint.sh: Launching /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh\n10-listen-on-ipv6-by-default.sh: info: Getting the checksum of /etc/nginx/conf.d/default.conf\n10-listen-on-ipv6-by-default.sh: info: Enabled listen on IPv6 in /etc/nginx/conf.d/default.conf\n/docker-entrypoint.sh: Launching /docker-entrypoint.d/20-envsubst-on-templates.sh\n/docker-entrypoint.sh: Launching /docker-entrypoint.d/30-tune-worker-processes.sh\n/docker-entrypoint.sh: Configuration complete; ready for start up\n2022/05/16 18:00:17 [notice] 1#1: using the "epoll" event method\n2022/05/16 18:00:17 [notice] 1#1: nginx/1.20.2\n2022/05/16 18:00:17 [notice] 1#1: built by gcc 10.2.1 20210110 (Debian 10.2.1-6)\n2022/05/16 18:00:17 [notice] 1#1: OS: Linux 5.10.102.1-microsoft-standard-WSL2\n2022/05/16 18:00:17 [notice] 1#1: getrlimit(RLIMIT_NOFILE): 1048576:1048576\n2022/05/16 18:00:17 [notice] 1#1: start worker processes\n2022/05/16 18:00:17 [notice] 1#1: start worker process 31\n2022/05/16 18:00:17 [notice] 1#1: start worker process 32\n2022/05/16 18:00:17 [notice] 1#1: start worker process 33\n2022/05/16 18:00:17 [notice] 1#1: start worker process 34\n2022/05/16 18:00:17 [notice] 1#1: start worker process 35\n2022/05/16 18:00:17 [notice] 1#1: start worker process 36\n2022/05/16 18:00:17 [notice] 1#1: start worker process 37\n2022/05/16 18:00:17 [notice] 1#1: start worker process 38\n2022/05/16 18:00:17 [notice] 38#38: signal 28 (SIGWINCH) received\n2022/05/16 18:00:17 [notice] 36#36: signal 28 (SIGWINCH) received\n2022/05/16 18:00:17 [notice] 33#33: signal 28 (SIGWINCH) received\n2022/05/16 18:00:17 [notice] 32#32: signal 28 (SIGWINCH) received\n2022/05/16 18:00:17 [notice] 34#34: signal 28 (SIGWINCH) received\n2022/05/16 18:00:17 [notice] 35#35: signal 28 (SIGWINCH) received\n2022/05/16 18:00:17 [notice] 37#37: signal 28 (SIGWINCH) received\n2022/05/16 18:00:17 [notice] 1#1: signal 28 (SIGWINCH) received\n2022/05/16 18:00:17 [notice] 31#31: signal 28 (SIGWINCH) received\n')),(0,r.kt)("p",{parentName:"li"},"You can stop the container by opening a new shell instance and running: ",(0,r.kt)("inlineCode",{parentName:"p"},"docker stop nginx-test")))))}d.isMDXComponent=!0}}]);