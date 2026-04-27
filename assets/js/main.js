var sectionHeight = function() {
    var total    = $(window).height(),
        $section = $('section').css('height','auto');
  
    if ($section.outerHeight(true) < total) {
      var margin = $section.outerHeight(true) - $section.height();
      $section.height(total - margin - 20);
    } else {
      $section.css('height','auto');
    }
  }
  
  $(window).resize(sectionHeight);
  
  $(function() {
    var slugCount = {};

      $("section h1, section h2, section h3").each(function(){
        var base = $(this).text().toLowerCase().replace(/ /g, '-').replace(/[^\w-]+/g, '');
        
        slugCount[base] = (slugCount[base] || 0) + 1;
        var slug = slugCount[base] > 1 ? base + '-' + slugCount[base] : base;

        $("nav ul").append("<li class='tag-" + this.nodeName.toLowerCase() + "'><a href='#" + slug + "'>" + $(this).text() + "</a></li>");
        $(this).attr("id", slug);
        $("nav ul li:first-child a").addClass("active");
    });
  
    $("nav ul li").on("click", "a", function(event) {
      var position = $($(this).attr("href")).offset().top - 190;
      $("html, body").animate({scrollTop: position}, 400);
      $("nav ul li a").removeClass("active");
      $(this).addClass("active");
      event.preventDefault();
    });
  
    sectionHeight();
  
    $('img').on('load', sectionHeight);
  });

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('pre.highlight').forEach(pre => {
    pre.addEventListener('click', e => {
      const fontSize = parseFloat(getComputedStyle(pre).fontSize)
      const beforeHeight = 1.75 * fontSize
      const preRect = pre.getBoundingClientRect()

      const relX = e.clientX - preRect.left
      const relY = e.clientY - preRect.top

      // Measure icon text width with matching font
      const ruler = document.createElement('span')
      ruler.style.cssText = `
        font-family: FontAwesome;
        font-size: ${fontSize}px;
        letter-spacing: 0.5em;
        visibility: hidden;
        position: absolute;
        white-space: nowrap;
      `
      ruler.textContent = '\uf057 \uf056 \uf13a '
      document.body.appendChild(ruler)
      const iconsWidth = ruler.getBoundingClientRect().width
      document.body.removeChild(ruler)

      const inBefore = relY <= beforeHeight && relX <= iconsWidth

      if (inBefore) {
        pre.classList.toggle('collapsed')
        console.log("click in icons region")
      }
    })
  })
})