// vue.config.js
module.exports = {
    configureWebpack: {
      // Definieren Sie die Feature-Flags für den ESM-Bundler-Build
      plugins: [
        new webpack.DefinePlugin({
          __VUE_OPTIONS_API__: 'true',  // Setzen Sie dies auf 'true', wenn Sie die Options-API verwenden
          __VUE_PROD_DEVTOOLS__: 'false', // Setzen Sie dies auf 'true', wenn Sie Devtools im Produktionsbundle möchten
          __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: 'false' // Setzen Sie dies auf 'true', wenn Sie Hydration Mismatch Details im Produktionsbundle möchten
        })
      ]
    }
  }
  