/// A chart that can be used to render some set of data.
#[derive(Clone, Copy)]
pub struct Chart {
    height: u32,
    full: char,
    half_full: char,
    space: char,
}

impl Chart {
    /// Creates a new chart.
    pub fn new() -> Chart {
        Chart {
            height: 10,
            full: '▌',
            half_full: '▖',
            space: ' ',
        }
    }

    /// Configure the height of the chart.
    pub fn height(mut self, h: u32) -> Chart {
        self.height = h;
        self
    }

    /// Build the chart into a string.
    pub fn make<N>(&self, data: &[N]) -> String
    where
        N: Into<f64> + Clone,
    {
        let data: Vec<f64> = data.iter().map(|d| d.clone().into()).collect();
        let (min, max): (f64, f64) = data.iter().fold((0., 0.), |(min, max), datum| {
            let datum = *datum;
            (
                if datum < min { datum } else { min },
                if max < datum { datum } else { max },
            )
        });
        let row_increment = (max - min) / f64::from(self.height);
        let mut ret = String::with_capacity(self.height as usize * data.len() * 2);
        for row in 0..self.height {
            let floor = max - (f64::from(row + 1) * row_increment);
            for datum in &data {
                ret.push(if *datum > floor {
                    if *datum > (floor + row_increment / 2.) {
                        self.full
                    } else {
                        self.half_full
                    }
                } else {
                    self.space
                });
            }
            if row == 0 {
                ret.push_str(&format!(" {}", max));
            }
            if row == self.height - 1 {
                ret.push_str(&format!(" {}", min));
            }
            ret.push('\n');
        }
        ret
    }
}
