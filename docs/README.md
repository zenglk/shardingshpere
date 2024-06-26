# ShardingSphere Documents

 ‍

#### HOW to build ShardingSphere website ?

To build ShardingSphere website by means of [hugo](http://gohugo.io/overview/introduction/) and [hugo theme learn](https://github.com/matcornic/hugo-theme-learn).

Follow the steps below to deploy ShardingSphere website, 

1. Execute `docs/build.sh` to generate `html` files at the directory of `docs/target/`.
2. Clone [shardingsphere-doc](https://github.com/apache/shardingsphere-doc.git).
3. Checkout to `asf-site` branch.
3. Overwrite `document/current` with `docs/target/document/current`, `community` with `docs/target/community` and `blog` with `docs/target/blog`.
4. Commit changes and raise a PR for [shardingsphere-doc](https://github.com/apache/shardingsphere-doc.git).

 ‍

#### Note :

1. If you modify `docs/build.sh`, please test it locally.

> shardingsphere-doc support docker hugo to build the website, you can use the following command to build:
> 1. Go to the root directory of `shardingsphere-doc`
> 2. Execute docker build command `docker build .github/docker/ -t docker-hugo:latest`
> 3. Execute `build-with-docker.sh` like `build.sh`
> 4. If test it locally, go to the directory container config.toml and execute command `docker run --rm -it -p1313:1313 --volume $(pwd):/opt/input docker-hugo:latest server --bind 0.0.0.0`

 ‍

#### HOW to insert a video of Bilibili or YouTube ?

1. First please make sure you get the correct url of the video you wanna add.

2. - DO REMEMBER use the `bvid argument` of bilibili url :

     for example : https://www.bilibili.com/video/BV1aE411X7kQ?from=search&seid=5978719442257399675 ( bvid argument means `BV1aE411X7kQ` , or you can simply recognize the argument with `Capital Letter` )

   - YouTube url is much easier to recognize : https://www.youtube.com/watch?v=2MsN8gpT6jY , the argument you needed is `2MsN8gpT6jY` at the end of the url.

3. Use the shortcodes at wherever you want to place :

   - `{{< bilibili BV1aE411X7kQ >}}`

   - `{{< youtube 2MsN8gpT6jY >}}`